package com.accessanalyzer.function;

import com.accessanalyzer.model.IHandler;
import com.accessanalyzer.model.IResponse;
import com.accessanalyzer.model.IRequest;
import com.accessanalyzer.model.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.io.*;
import java.nio.file.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Handler extends com.accessanalyzer.model.AbstractHandler {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String SECRETS_DIR = "/var/openfaas/secrets/";
    
    public IResponse Handle(IRequest req) {
        try {
            // Create context from environment variables
            Context context = new Context();
            context.setHostname(System.getenv().getOrDefault("HOSTNAME", "localhost"));
            context.setScanId(System.getenv("SCAN_ID"));
            context.setSyncId(System.getenv("SYNC_ID"));
            context.setRunLocal(System.getenv().getOrDefault("RUN_LOCAL", "false"));
            context.setFunctionType(System.getenv("FUNCTION_TYPE"));
            
            // Parse CONFIG
            String configStr = System.getenv("CONFIG");
            if (configStr != null && !configStr.isEmpty()) {
                try {
                    JsonNode configJson = objectMapper.readTree(configStr);
                    context.setConfig(configJson);
                } catch (Exception e) {
                    return createErrorResponse(400, "Invalid JSON in CONFIG: " + e.getMessage());
                }
            }

            boolean localRun = "true".equals(context.getRunLocal());

            if (localRun) {
                if (context.getConfig() == null) {
                    return createErrorResponse(400, "CONFIG is required when RUN_LOCAL is true");
                }

                if (context.getFunctionType() == null || context.getFunctionType().isEmpty()) {
                    return createErrorResponse(400, "FUNCTION_TYPE is required when RUN_LOCAL is true");
                }

                // Validate request body against config
                String requestBody = req.getBody();
                if (requestBody != null && !requestBody.isEmpty()) {
                    try {
                        JsonNode requestData = objectMapper.readTree(requestBody);
                        ValidationResult validation = LocalTesting.validateRequestSchema(
                            context.getConfig(), requestData, context.getFunctionType());
                        if (!validation.isValid()) {
                            return createErrorResponse(400, validation.getErrorMessage());
                        }
                    } catch (Exception e) {
                        return createErrorResponse(400, "Invalid JSON in request body: " + e.getMessage());
                    }
                }
            }

            // Load secrets from OpenFaaS secret files
            context.setSecrets(getSecrets(localRun));

            // Parse execution IDs from request body
            String requestBody = req.getBody();
            if (requestBody != null && !requestBody.isEmpty()) {
                try {
                    JsonNode requestData = objectMapper.readTree(requestBody);
                    if (requestData.has("scanExecutionId")) {
                        context.setScanExecutionId(requestData.get("scanExecutionId").asText());
                    }
                    if (requestData.has("syncExecutionId")) {
                        context.setSyncExecutionId(requestData.get("syncExecutionId").asText());
                    }
                } catch (Exception e) {
                    // Ignore JSON parsing errors for execution IDs
                }
            }

            if (context.getSecrets().isEmpty()) {
                System.out.println("Warning: No secrets loaded from secret files");
            } else {
                System.out.println("Loaded " + context.getSecrets().size() + " secrets from secret files");
            }

            String startedAt = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
            IResponse responseData = handleFunction(req, context);
            String completedAt = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);

            System.out.println("Response data: " + responseData);

            // Add timestamps for successful responses
            if ("test-connection".equals(context.getFunctionType()) && responseData.getStatusCode() == 200) {
                addTimestampsToResponse(responseData, startedAt, completedAt);
            } else if ("access-scan".equals(context.getFunctionType()) && responseData.getStatusCode() == 200) {
                addTimestampsToResponse(responseData, startedAt, completedAt);
            }

            if (localRun) {
                ValidationResult validation = LocalTesting.validateResponse(context.getFunctionType(), responseData);
                if (!validation.isValid()) {
                    responseData = context.errorResponse(false, validation.getErrorMessage());
                }
            }

            return responseData;

        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse(500, "Internal server error: " + e.getMessage());
        }
    }

    private IResponse createErrorResponse(int statusCode, String errorMessage) {
        Response response = new Response();
        response.setStatusCode(statusCode);
        Map<String, Object> body = new HashMap<>();
        body.put("error", errorMessage);
        response.setBody(objectMapper.valueToTree(body).toString());
        return response;
    }

    private void addTimestampsToResponse(IResponse response, String startedAt, String completedAt) {
        try {
            String bodyStr = response.getBody();
            JsonNode bodyJson;
            if (bodyStr == null || bodyStr.isEmpty()) {
                bodyJson = objectMapper.createObjectNode();
            } else {
                bodyJson = objectMapper.readTree(bodyStr);
            }
            
            if (bodyJson.isObject()) {
                ((com.fasterxml.jackson.databind.node.ObjectNode) bodyJson).put("startedAt", startedAt);
                ((com.fasterxml.jackson.databind.node.ObjectNode) bodyJson).put("completedAt", completedAt);
                response.setBody(bodyJson.toString());
            }
        } catch (Exception e) {
            System.err.println("Error adding timestamps to response: " + e.getMessage());
        }
    }

    private Map<String, String> getSecrets(boolean localRun) {
        Map<String, String> secrets = new HashMap<>();
        
        try {
            Path secretsPath = Paths.get(SECRETS_DIR);
            if (!Files.exists(secretsPath)) {
                System.out.println("Secrets directory does not exist: " + SECRETS_DIR);
                return secrets;
            }

            Files.list(secretsPath)
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    String filename = file.getFileName().toString();
                    
                    String keyName;
                    if (localRun) {
                        // For local run, use the filename as-is (no scan ID removal)
                        keyName = filename;
                    } else {
                        // For non-local run, remove the last 9 characters (dash + 8 chars scan ID)
                        if (filename.length() > 9 && filename.charAt(filename.length() - 9) == '-') {
                            keyName = filename.substring(0, filename.length() - 9);
                        } else {
                            System.out.println("Skipping secret file with unexpected format: " + filename);
                            return;
                        }
                    }

                    // Convert dash-separated to camelCase
                    String[] keyParts = keyName.split("-");
                    String camelKey;
                    if (keyParts.length > 1) {
                        camelKey = keyParts[0];
                        for (int i = 1; i < keyParts.length; i++) {
                            camelKey += keyParts[i].substring(0, 1).toUpperCase() + keyParts[i].substring(1);
                        }
                    } else {
                        camelKey = keyParts[0];
                    }

                    // Read the secret content
                    try {
                        String content = Files.readString(file).trim();
                        secrets.put(camelKey, content);
                        System.out.println("Loaded secret: " + camelKey);
                    } catch (IOException e) {
                        System.err.println("Error reading secret file " + filename + ": " + e.getMessage());
                    }
                });

        } catch (IOException e) {
            System.err.println("Error reading secrets directory: " + e.getMessage());
        }

        return secrets;
    }

    // Placeholder for the actual function implementation
    private IResponse handleFunction(IRequest req, Context context) {
        Response res = new Response();
        res.setStatusCode(200);
        Map<String, Object> body = new HashMap<>();
        body.put("message", "Hello from Netwrix Java handler");
        res.setBody(objectMapper.valueToTree(body).toString());
        return res;
    }

    // Context class to hold request context information
    public static class Context {
        private String hostname;
        private Map<String, String> secrets = new HashMap<>();
        private String scanId;
        private String syncId;
        private String scanExecutionId;
        private String syncExecutionId;
        private String runLocal;
        private JsonNode config;
        private String functionType;

        // Getters and setters
        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        
        public Map<String, String> getSecrets() { return secrets; }
        public void setSecrets(Map<String, String> secrets) { this.secrets = secrets; }
        
        public String getScanId() { return scanId; }
        public void setScanId(String scanId) { this.scanId = scanId; }
        
        public String getSyncId() { return syncId; }
        public void setSyncId(String syncId) { this.syncId = syncId; }
        
        public String getScanExecutionId() { return scanExecutionId; }
        public void setScanExecutionId(String scanExecutionId) { this.scanExecutionId = scanExecutionId; }
        
        public String getSyncExecutionId() { return syncExecutionId; }
        public void setSyncExecutionId(String syncExecutionId) { this.syncExecutionId = syncExecutionId; }
        
        public String getRunLocal() { return runLocal; }
        public void setRunLocal(String runLocal) { this.runLocal = runLocal; }
        
        public JsonNode getConfig() { return config; }
        public void setConfig(JsonNode config) { this.config = config; }
        
        public String getFunctionType() { return functionType; }
        public void setFunctionType(String functionType) { this.functionType = functionType; }

        public IResponse testConnectionSuccessResponse() {
            Response response = new Response();
            response.setStatusCode(200);
            response.setBody("{}");
            return response;
        }

        public IResponse accessScanSuccessResponse() {
            Response response = new Response();
            response.setStatusCode(200);
            response.setBody("{}");
            return response;
        }

        public IResponse getObjectSuccessResponse(byte[] data) {
            Response response = new Response();
            response.setStatusCode(200);
            String encodedData = Base64.getEncoder().encodeToString(data);
            Map<String, Object> body = new HashMap<>();
            body.put("data", encodedData);
            try {
                response.setBody(objectMapper.writeValueAsString(body));
            } catch (Exception e) {
                response.setBody("{\"data\":\"" + encodedData + "\"}");
            }
            return response;
        }

        public IResponse errorResponse(boolean clientError, String errorMsg) {
            Response response = new Response();
            response.setStatusCode(clientError ? 400 : 500);
            Map<String, Object> body = new HashMap<>();
            body.put("error", errorMsg);
            try {
                response.setBody(objectMapper.writeValueAsString(body));
            } catch (Exception e) {
                response.setBody("{\"error\":\"" + errorMsg.replace("\"", "\\\"") + "\"}");
            }
            return response;
        }

        public SaveDataResult saveData(List<Map<String, Object>> data) {
            // Add scan_id, scan_execution_id, and scanned_at to each row
            List<Map<String, Object>> enhancedData = new ArrayList<>();
            String currentTime = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);

            boolean localRun = "true".equals(this.runLocal);
            String scanId = localRun ? "scan0001" : this.scanId;
            String scanExecutionId = localRun ? "scan-0002" : this.scanExecutionId;

            for (Map<String, Object> row : data) {
                Map<String, Object> enhancedRow = new HashMap<>();
                enhancedRow.put("scan_id", scanId);
                enhancedRow.put("scan_execution_id", scanExecutionId);
                enhancedRow.put("scanned_at", currentTime);
                enhancedRow.putAll(row);
                enhancedData.add(enhancedRow);
            }

            // Dev environment validation
            if (localRun) {
                ValidationResult validation = LocalTesting.validateDevData(this.config, enhancedData);
                if (!validation.isValid()) {
                    System.out.println(validation.getErrorMessage());
                    return new SaveDataResult(false, validation.getErrorMessage());
                } else {
                    System.out.println("Saving " + enhancedData.size() + " items to table");
                    if (!enhancedData.isEmpty()) {
                        try {
                            String sampleJson = objectMapper.writerWithDefaultPrettyPrinter()
                                .writeValueAsString(enhancedData.get(0));
                            System.out.println("Sample item: " + sampleJson);
                        } catch (Exception e) {
                            System.out.println("Sample item: " + enhancedData.get(0));
                        }
                    }
                    return new SaveDataResult(true, null);
                }
            } else {
                String saveDataFunction = System.getenv("SAVE_DATA_FUNCTION");
                if (saveDataFunction == null || saveDataFunction.isEmpty()) {
                    String errorMsg = "SAVE_DATA_FUNCTION is not in the environment";
                    System.out.println(errorMsg);
                    return new SaveDataResult(false, errorMsg);
                }

                Map<String, Object> payload = new HashMap<>();
                payload.put("sourceType", System.getenv("SOURCE_TYPE"));
                payload.put("version", System.getenv("SOURCE_VERSION"));
                payload.put("table", "access");
                payload.put("data", enhancedData);

                try {
                    String payloadJson = objectMapper.writeValueAsString(payload);
                    String url = System.getenv("OPENFAAS_GATEWAY") + "/async-function/" + saveDataFunction;

                    HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(java.time.Duration.ofSeconds(30))
                        .build();

                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payloadJson))
                        .timeout(java.time.Duration.ofSeconds(30))
                        .build();

                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() == 202) {
                        return new SaveDataResult(true, null);
                    } else {
                        String errorMsg = "Status " + response.statusCode() + ": " + response.body();
                        System.out.println(errorMsg);
                        return new SaveDataResult(false, errorMsg);
                    }
                } catch (Exception e) {
                    String errorMsg = "Error: " + e.getMessage();
                    System.out.println(errorMsg);
                    return new SaveDataResult(false, errorMsg);
                }
            }
        }

        public UpdateExecutionResult updateExecution(String status, Integer totalObjects, 
                Integer completedObjects, Integer incrementCompletedObjects, String completedAt) {
            // Validation for dev environment
            if ("true".equals(this.runLocal)) {
                ValidationResult validation = LocalTesting.validateUpdateExecutionParams(
                    status, totalObjects, completedObjects, incrementCompletedObjects, completedAt);
                if (!validation.isValid()) {
                    System.out.println(validation.getErrorMessage());
                    return new UpdateExecutionResult(false, validation.getErrorMessage());
                } else {
                    return new UpdateExecutionResult(true, null);
                }
            } else {
                String appUpdateFunction = System.getenv("APP_UPDATE_EXECUTION_FUNCTION");
                if (appUpdateFunction == null || appUpdateFunction.isEmpty()) {
                    String errorMsg = "APP_UPDATE_EXECUTION_FUNCTION is not in the environment";
                    System.out.println(errorMsg);
                    return new UpdateExecutionResult(false, errorMsg);
                }

                String executionId;
                String executionType;

                if (this.scanExecutionId != null && !this.scanExecutionId.isEmpty()) {
                    executionId = this.scanExecutionId;
                    executionType = "scan";
                } else if (this.syncExecutionId != null && !this.syncExecutionId.isEmpty()) {
                    executionId = this.syncExecutionId;
                    executionType = "sync";
                } else {
                    String errorMsg = "Missing required field: either 'scanExecutionId' or 'syncExecutionId' must be provided";
                    System.out.println(errorMsg);
                    return new UpdateExecutionResult(false, errorMsg);
                }

                Map<String, Object> payload = new HashMap<>();
                payload.put("type", executionType);
                payload.put("executionId", executionId);

                // Only include optional fields if they are provided (not null)
                if (status != null) payload.put("status", status);
                if (totalObjects != null) payload.put("totalObjects", totalObjects);
                if (completedObjects != null) payload.put("completedObjects", completedObjects);
                if (incrementCompletedObjects != null) payload.put("incrementCompletedObjects", incrementCompletedObjects);
                if (completedAt != null) payload.put("completedAt", completedAt);

                try {
                    String payloadJson = objectMapper.writeValueAsString(payload);
                    String url = System.getenv("OPENFAAS_GATEWAY") + "/async-function/" + appUpdateFunction;

                    HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(java.time.Duration.ofSeconds(30))
                        .build();

                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payloadJson))
                        .timeout(java.time.Duration.ofSeconds(30))
                        .build();

                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() == 202) {
                        return new UpdateExecutionResult(true, null);
                    } else {
                        String errorMsg = "Status " + response.statusCode() + ": " + response.body();
                        System.out.println(errorMsg);
                        return new UpdateExecutionResult(false, errorMsg);
                    }
                } catch (Exception e) {
                    String errorMsg = "Error: " + e.getMessage();
                    System.out.println(errorMsg);
                    return new UpdateExecutionResult(false, errorMsg);
                }
            }
        }
    }

    // Result classes
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;

        public ValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public boolean isValid() { return valid; }
        public String getErrorMessage() { return errorMessage; }
    }

    public static class SaveDataResult {
        private final boolean success;
        private final String errorMessage;

        public SaveDataResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() { return success; }
        public String getErrorMessage() { return errorMessage; }
    }

    public static class UpdateExecutionResult {
        private final boolean success;
        private final String errorMessage;

        public UpdateExecutionResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() { return success; }
        public String getErrorMessage() { return errorMessage; }
    }
}