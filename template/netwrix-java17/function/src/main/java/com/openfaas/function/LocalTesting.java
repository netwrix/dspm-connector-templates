package com.accessanalyzer.function;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.accessanalyzer.model.IResponse;

import java.util.*;
import java.util.regex.Pattern;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class LocalTesting {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static Handler.ValidationResult validateRequestSchema(JsonNode config, JsonNode requestData, String functionType) {
        if (requestData == null || !requestData.isObject()) {
            return new Handler.ValidationResult(false, "Request body must be a JSON object");
        }

        if (functionType == null || functionType.isEmpty()) {
            return new Handler.ValidationResult(false, "Missing FUNCTION_TYPE environment variable");
        }

        List<String> validFunctions = Arrays.asList("test-connection", "access-scan", "get-object");
        if (!validFunctions.contains(functionType)) {
            return new Handler.ValidationResult(false, "Invalid function type. Must be one of: " + validFunctions);
        }

        // Define allowed top-level properties for each function type
        Map<String, List<String>> allowedProperties = new HashMap<>();
        allowedProperties.put("test-connection", Arrays.asList("connection"));
        allowedProperties.put("access-scan", Arrays.asList("connection", "accessScan"));
        allowedProperties.put("get-object", Arrays.asList("connection", "location"));

        // Check for additional properties at the top level
        List<String> expectedProperties = allowedProperties.get(functionType);
        List<String> extraProperties = new ArrayList<>();
        
        Iterator<String> fieldNames = requestData.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            if (!expectedProperties.contains(fieldName)) {
                extraProperties.add(fieldName);
            }
        }

        if (!extraProperties.isEmpty()) {
            Collections.sort(extraProperties);
            return new Handler.ValidationResult(false, 
                "Additional properties not allowed for " + functionType + ": " + extraProperties);
        }

        // Validate connection object (required for all functions)
        if (!requestData.has("connection")) {
            return new Handler.ValidationResult(false, "Missing required field: 'connection'");
        }

        JsonNode connectionData = requestData.get("connection");
        if (!connectionData.isObject()) {
            return new Handler.ValidationResult(false, "'connection' must be an object");
        }

        // Validate connection fields against config.variables.connection
        if (config.has("variables") && config.get("variables").has("connection")) {
            JsonNode connectionConfig = config.get("variables").get("connection");
            if (connectionConfig.isArray()) {
                Handler.ValidationResult result = validateObjectAgainstSchema(connectionData, connectionConfig, "connection");
                if (!result.isValid()) {
                    return result;
                }
            }
        }

        // Function-specific validation
        if ("access-scan".equals(functionType)) {
            if (!requestData.has("accessScan")) {
                return new Handler.ValidationResult(false, "Missing required field: 'accessScan' for access-scan function");
            }

            JsonNode accessScanData = requestData.get("accessScan");
            if (!accessScanData.isObject()) {
                return new Handler.ValidationResult(false, "'accessScan' must be an object");
            }

            // Validate accessScan fields against config.variables.accessScan
            if (config.has("variables") && config.get("variables").has("accessScan")) {
                JsonNode accessScanConfig = config.get("variables").get("accessScan");
                if (accessScanConfig.isArray()) {
                    Handler.ValidationResult result = validateObjectAgainstSchema(accessScanData, accessScanConfig, "accessScan");
                    if (!result.isValid()) {
                        return result;
                    }
                }
            }
        } else if ("get-object".equals(functionType)) {
            if (!requestData.has("location")) {
                return new Handler.ValidationResult(false, "Missing required field: 'location' for get-object function");
            }

            JsonNode locationData = requestData.get("location");
            if (!locationData.isObject()) {
                return new Handler.ValidationResult(false, "'location' must be an object");
            }

            // Validate location fields against config.getObjectColumns
            if (config.has("getObjectColumns")) {
                JsonNode getObjectColumns = config.get("getObjectColumns");
                if (getObjectColumns.isArray()) {
                    Handler.ValidationResult result = validateLocationAgainstColumns(locationData, getObjectColumns);
                    if (!result.isValid()) {
                        return result;
                    }
                }
            }
        }

        return new Handler.ValidationResult(true, null);
    }

    private static Handler.ValidationResult validateObjectAgainstSchema(JsonNode data, JsonNode schemaConfig, String fieldName) {
        // Get list of allowed field keys from schema
        Set<String> allowedKeys = new HashSet<>();
        for (JsonNode fieldConfig : schemaConfig) {
            if (fieldConfig.has("key")) {
                allowedKeys.add(fieldConfig.get("key").asText());
            }
        }

        // Check for additional properties not in schema
        List<String> extraKeys = new ArrayList<>();
        Iterator<String> fieldNames = data.fieldNames();
        while (fieldNames.hasNext()) {
            String key = fieldNames.next();
            if (!allowedKeys.contains(key)) {
                extraKeys.add(key);
            }
        }

        if (!extraKeys.isEmpty()) {
            Collections.sort(extraKeys);
            return new Handler.ValidationResult(false, 
                "Additional properties not allowed in '" + fieldName + "': " + extraKeys);
        }

        // Validate each field in schema
        for (JsonNode fieldConfig : schemaConfig) {
            if (!fieldConfig.has("key")) continue;

            String fieldKey = fieldConfig.get("key").asText();
            String fieldType = fieldConfig.has("type") ? fieldConfig.get("type").asText() : "";
            boolean required = fieldConfig.has("required") && fieldConfig.get("required").asBoolean();

            JsonNode value = data.get(fieldKey);

            // Check required fields
            if (required && (value == null || value.isNull() || (value.isTextual() && value.asText().isEmpty()))) {
                return new Handler.ValidationResult(false, "Missing required field: '" + fieldName + "." + fieldKey + "'");
            }

            // Skip validation for optional fields that are not provided
            if ((value == null || value.isNull()) && !required) {
                continue;
            }

            // Type validation
            if ("text".equals(fieldType) || "string".equals(fieldType)) {
                if (!value.isTextual()) {
                    return new Handler.ValidationResult(false, 
                        "Field '" + fieldName + "." + fieldKey + "' must be a string, got " + value.getNodeType());
                }
            } else if ("number".equals(fieldType)) {
                if (!value.isNumber()) {
                    return new Handler.ValidationResult(false, 
                        "Field '" + fieldName + "." + fieldKey + "' must be a number, got " + value.getNodeType());
                }

                // Check min/max constraints
                if (fieldConfig.has("min")) {
                    double minVal = fieldConfig.get("min").asDouble();
                    if (value.asDouble() < minVal) {
                        return new Handler.ValidationResult(false, 
                            "Field '" + fieldName + "." + fieldKey + "' must be >= " + minVal + ", got " + value.asDouble());
                    }
                }

                if (fieldConfig.has("max")) {
                    double maxVal = fieldConfig.get("max").asDouble();
                    if (value.asDouble() > maxVal) {
                        return new Handler.ValidationResult(false, 
                            "Field '" + fieldName + "." + fieldKey + "' must be <= " + maxVal + ", got " + value.asDouble());
                    }
                }
            } else if ("checkbox".equals(fieldType)) {
                if (!value.isBoolean()) {
                    return new Handler.ValidationResult(false, 
                        "Field '" + fieldName + "." + fieldKey + "' must be a boolean, got " + value.getNodeType());
                }
            } else if ("list".equals(fieldType)) {
                if (value != null && !value.isNull()) {
                    List<JsonNode> valueList = new ArrayList<>();
                    if (value.isTextual()) {
                        valueList.add(value);
                    } else if (value.isArray()) {
                        for (JsonNode item : value) {
                            valueList.add(item);
                        }
                    } else {
                        return new Handler.ValidationResult(false, 
                            "Field '" + fieldName + "." + fieldKey + "' must be a string or array, got " + value.getNodeType());
                    }

                    // Validate options if specified
                    if (fieldConfig.has("options")) {
                        JsonNode options = fieldConfig.get("options");
                        if (options.isArray()) {
                            List<String> validValues = new ArrayList<>();
                            for (JsonNode opt : options) {
                                if (opt.has("value")) {
                                    validValues.add(opt.get("value").asText());
                                }
                            }

                            if (!validValues.isEmpty()) {
                                for (JsonNode val : valueList) {
                                    if (val.isTextual() && !validValues.contains(val.asText())) {
                                        return new Handler.ValidationResult(false, 
                                            "Field '" + fieldName + "." + fieldKey + "' contains invalid value '" + val.asText() + "'. Valid options: " + validValues);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return new Handler.ValidationResult(true, null);
    }

    private static Handler.ValidationResult validateLocationAgainstColumns(JsonNode locationData, JsonNode getObjectColumns) {
        // Convert getObjectColumns to string list
        List<String> expectedColumns = new ArrayList<>();
        for (JsonNode col : getObjectColumns) {
            if (col.isTextual()) {
                expectedColumns.add(col.asText());
            }
        }

        // Get actual columns in order
        List<String> actualColumns = new ArrayList<>();
        Iterator<String> fieldNames = locationData.fieldNames();
        while (fieldNames.hasNext()) {
            actualColumns.add(fieldNames.next());
        }

        // Check that all expected columns are present and in the correct order
        if (actualColumns.size() != expectedColumns.size()) {
            return new Handler.ValidationResult(false, 
                "Location must contain exactly " + expectedColumns.size() + " columns. Expected: " + expectedColumns + ", Got: " + actualColumns);
        }

        // Check order and presence of columns
        for (int i = 0; i < expectedColumns.size(); i++) {
            if (i >= actualColumns.size() || !actualColumns.get(i).equals(expectedColumns.get(i))) {
                return new Handler.ValidationResult(false, 
                    "Location columns must match order and names. Expected: " + expectedColumns + ", Got: " + actualColumns);
            }
        }

        // Validate that all values are strings (column values)
        for (Iterator<Map.Entry<String, JsonNode>> it = locationData.fields(); it.hasNext();) {
            Map.Entry<String, JsonNode> entry = it.next();
            if (!entry.getValue().isTextual()) {
                return new Handler.ValidationResult(false, 
                    "Location column '" + entry.getKey() + "' must be a string, got " + entry.getValue().getNodeType());
            }
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateUpdateExecutionParams(String status, Integer totalObjects, 
            Integer completedObjects, Integer incrementCompletedObjects, String completedAt) {
        
        // Validate status
        if (status != null) {
            List<String> validStatuses = Arrays.asList("running", "completed", "failed");
            if (!validStatuses.contains(status)) {
                return new Handler.ValidationResult(false, 
                    "Invalid status: '" + status + "'. Must be one of: " + validStatuses);
            }
        }

        // Validate total_objects
        if (totalObjects != null && totalObjects < 0) {
            return new Handler.ValidationResult(false, 
                "total_objects must be a non-negative integer, got: " + totalObjects);
        }

        // Validate completed_objects
        if (completedObjects != null && completedObjects < 0) {
            return new Handler.ValidationResult(false, 
                "completed_objects must be a non-negative integer, got: " + completedObjects);
        }

        // Validate increment_completed_objects
        if (incrementCompletedObjects != null && incrementCompletedObjects < 0) {
            return new Handler.ValidationResult(false, 
                "increment_completed_objects must be a non-negative integer, got: " + incrementCompletedObjects);
        }

        // Check that only one of completed_objects or increment_completed_objects is provided
        if (completedObjects != null && incrementCompletedObjects != null) {
            return new Handler.ValidationResult(false, 
                "Only one of completed_objects or increment_completed_objects can be provided, not both");
        }

        // Check that completed_objects is not greater than total_objects
        if (totalObjects != null && completedObjects != null && completedObjects > totalObjects) {
            return new Handler.ValidationResult(false, 
                "completed_objects (" + completedObjects + ") cannot be greater than total_objects (" + totalObjects + ")");
        }

        // Validate completed_at ISO8601 format
        if (completedAt != null) {
            String iso8601Pattern = "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2}))$";
            if (!Pattern.matches(iso8601Pattern, completedAt)) {
                return new Handler.ValidationResult(false, 
                    "completed_at must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '" + completedAt + "'");
            }

            // Additional validation by attempting to parse
            try {
                Instant.parse(completedAt);
            } catch (DateTimeParseException e) {
                return new Handler.ValidationResult(false, 
                    "completed_at is not a valid ISO8601 datetime: '" + completedAt + "'");
            }
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateGetObjectResponse(IResponse responseData) {
        try {
            if (responseData.getBody() == null || responseData.getBody().isEmpty()) {
                return new Handler.ValidationResult(false, "Response must contain a 'body' property");
            }

            JsonNode body = objectMapper.readTree(responseData.getBody());
            if (!body.isObject()) {
                return new Handler.ValidationResult(false, "Response body must be a dictionary");
            }

            // Check that body contains only 'data' property
            List<String> extraKeys = new ArrayList<>();
            boolean hasData = false;

            Iterator<String> fieldNames = body.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                if ("data".equals(key)) {
                    hasData = true;
                } else {
                    extraKeys.add(key);
                }
            }

            if (!extraKeys.isEmpty()) {
                Collections.sort(extraKeys);
                return new Handler.ValidationResult(false, "Response body contains additional properties: " + extraKeys);
            }

            if (!hasData) {
                return new Handler.ValidationResult(false, "Response body must contain a 'data' property");
            }

            JsonNode dataValue = body.get("data");

            // Validate that data is a string
            if (!dataValue.isTextual()) {
                return new Handler.ValidationResult(false, "Response body.data must be a string, got " + dataValue.getNodeType());
            }

            String dataStr = dataValue.asText();

            // Validate that data is not empty
            if (dataStr.isEmpty()) {
                return new Handler.ValidationResult(false, "Response body.data cannot be empty");
            }

            // Check base64 format using regex
            String base64Pattern = "^[A-Za-z0-9+/]*={0,2}$";
            if (!Pattern.matches(base64Pattern, dataStr)) {
                return new Handler.ValidationResult(false, "Response body.data is not valid base64 format");
            }

            // Try to decode to verify it's valid base64
            try {
                Base64.getDecoder().decode(dataStr);
            } catch (IllegalArgumentException e) {
                return new Handler.ValidationResult(false, "Response body.data is not valid base64 encoding");
            }

        } catch (Exception e) {
            return new Handler.ValidationResult(false, "Error parsing response body: " + e.getMessage());
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateTestConnectionResponse(IResponse responseData) {
        return validateTimestampResponse(responseData, "test-connection");
    }

    public static Handler.ValidationResult validateAccessScanResponse(IResponse responseData) {
        return validateTimestampResponse(responseData, "access-scan");
    }

    private static Handler.ValidationResult validateTimestampResponse(IResponse responseData, String functionType) {
        try {
            if (responseData.getBody() == null || responseData.getBody().isEmpty()) {
                return new Handler.ValidationResult(false, "Response must contain a 'body' property");
            }

            JsonNode body = objectMapper.readTree(responseData.getBody());
            if (!body.isObject()) {
                return new Handler.ValidationResult(false, "Response body must be a dictionary");
            }

            // Check that body contains only required properties
            Set<String> requiredKeys = new HashSet<>(Arrays.asList("startedAt", "completedAt"));
            List<String> missingKeys = new ArrayList<>();
            List<String> extraKeys = new ArrayList<>();

            // Check for missing and extra keys
            for (String key : requiredKeys) {
                if (!body.has(key)) {
                    missingKeys.add(key);
                }
            }

            Iterator<String> fieldNames = body.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                if (!requiredKeys.contains(key)) {
                    extraKeys.add(key);
                }
            }

            if (!missingKeys.isEmpty()) {
                Collections.sort(missingKeys);
                return new Handler.ValidationResult(false, "Response body missing required properties: " + missingKeys);
            }

            if (!extraKeys.isEmpty()) {
                Collections.sort(extraKeys);
                return new Handler.ValidationResult(false, "Response body contains additional properties: " + extraKeys);
            }

            // Validate datetime formats (ISO8601)
            String iso8601Pattern = "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2}))$";

            for (String fieldName : Arrays.asList("startedAt", "completedAt")) {
                JsonNode fieldValue = body.get(fieldName);

                // Validate that field is a string
                if (!fieldValue.isTextual()) {
                    return new Handler.ValidationResult(false, 
                        "Response body." + fieldName + " must be a string, got " + fieldValue.getNodeType());
                }

                String fieldStr = fieldValue.asText();

                // Validate ISO8601 format
                if (!Pattern.matches(iso8601Pattern, fieldStr)) {
                    return new Handler.ValidationResult(false, 
                        "Response body." + fieldName + " must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '" + fieldStr + "'");
                }

                // Additional validation by attempting to parse
                try {
                    Instant.parse(fieldStr);
                } catch (DateTimeParseException e) {
                    return new Handler.ValidationResult(false, 
                        "Response body." + fieldName + " is not a valid ISO8601 datetime: '" + fieldStr + "'");
                }
            }

            // Validate that completedAt is after startedAt
            try {
                Instant startedAt = Instant.parse(body.get("startedAt").asText());
                Instant completedAt = Instant.parse(body.get("completedAt").asText());

                if (completedAt.isBefore(startedAt)) {
                    return new Handler.ValidationResult(false, 
                        "Response body.completedAt (" + body.get("completedAt").asText() + ") must be after startedAt (" + body.get("startedAt").asText() + ")");
                }
            } catch (DateTimeParseException e) {
                // If we can't parse for comparison, we've already validated format above
            }

        } catch (Exception e) {
            return new Handler.ValidationResult(false, "Error parsing response body: " + e.getMessage());
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateErrorResponse(IResponse responseData) {
        try {
            if (responseData.getBody() == null || responseData.getBody().isEmpty()) {
                return new Handler.ValidationResult(false, "Response must contain a 'body' property");
            }

            JsonNode body = objectMapper.readTree(responseData.getBody());
            if (!body.isObject()) {
                return new Handler.ValidationResult(false, "Response body must be a dictionary");
            }

            // Check that body contains only the required property
            boolean hasError = false;
            List<String> extraKeys = new ArrayList<>();

            Iterator<String> fieldNames = body.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                if ("error".equals(key)) {
                    hasError = true;
                } else {
                    extraKeys.add(key);
                }
            }

            if (!hasError) {
                return new Handler.ValidationResult(false, "Response body missing required properties: [error]");
            }

            if (!extraKeys.isEmpty()) {
                Collections.sort(extraKeys);
                return new Handler.ValidationResult(false, "Response body contains additional properties: " + extraKeys);
            }

            // Validate error field
            JsonNode errorMessage = body.get("error");

            // Validate that error is a string
            if (!errorMessage.isTextual()) {
                return new Handler.ValidationResult(false, "Response body.error must be a string, got " + errorMessage.getNodeType());
            }

            // Validate that error is not empty
            if (errorMessage.asText().trim().isEmpty()) {
                return new Handler.ValidationResult(false, "Response body.error cannot be empty");
            }

        } catch (Exception e) {
            return new Handler.ValidationResult(false, "Error parsing response body: " + e.getMessage());
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateDevData(JsonNode config, List<Map<String, Object>> data) {
        // Intelligence is now an array of columns, table name is always 'access'
        if (!config.has("intelligence")) {
            return new Handler.ValidationResult(false, "No columns found in config.intelligence");
        }

        JsonNode intelligence = config.get("intelligence");
        if (!intelligence.isArray()) {
            return new Handler.ValidationResult(false, "config.intelligence must be an array");
        }

        if (intelligence.size() == 0) {
            return new Handler.ValidationResult(false, "No columns found in config.intelligence");
        }

        // Validate data is an array of objects
        if (data.isEmpty()) {
            return new Handler.ValidationResult(false, "Data array cannot be empty");
        }

        // Validate first object matches expected columns and data types
        Map<String, Object> firstObject = data.get(0);

        // The actual data will have scan_id, scan_execution_id, and scanned_at added by save_data
        List<String> expectedTrackingFields = Arrays.asList("scan_id", "scan_execution_id", "scanned_at");
        List<String> expectedColumnNames = new ArrayList<>(expectedTrackingFields);

        for (JsonNode col : intelligence) {
            if (col.has("name")) {
                expectedColumnNames.add(col.get("name").asText());
            }
        }

        List<String> actualColumns = new ArrayList<>(firstObject.keySet());

        // Check column names match and are in the same order
        if (actualColumns.size() != expectedColumnNames.size()) {
            return new Handler.ValidationResult(false, 
                "Column names/order mismatch. Expected: " + expectedColumnNames + ", Got: " + actualColumns);
        }

        for (int i = 0; i < expectedColumnNames.size(); i++) {
            if (i >= actualColumns.size() || !actualColumns.get(i).equals(expectedColumnNames.get(i))) {
                return new Handler.ValidationResult(false, 
                    "Column names/order mismatch. Expected: " + expectedColumnNames + ", Got: " + actualColumns);
            }
        }

        // Validate tracking fields first
        Map<String, String> trackingFieldTypes = new HashMap<>();
        trackingFieldTypes.put("scan_id", "LowCardinality(String)");
        trackingFieldTypes.put("scan_execution_id", "LowCardinality(String)");
        trackingFieldTypes.put("scanned_at", "DateTime");

        for (Map.Entry<String, String> entry : trackingFieldTypes.entrySet()) {
            String fieldName = entry.getKey();
            String fieldType = entry.getValue();
            Object value = firstObject.get(fieldName);

            if (value == null) {
                return new Handler.ValidationResult(false, "Required tracking field '" + fieldName + "' is missing");
            }

            Handler.ValidationResult result = validateClickHouseType(fieldName, fieldType, value);
            if (!result.isValid()) {
                return result;
            }
        }

        // Validate data types for each column from intelligence config
        for (JsonNode col : intelligence) {
            if (!col.has("name") || !col.has("type")) {
                continue;
            }

            String columnName = col.get("name").asText();
            String expectedType = col.get("type").asText();
            boolean nullable = !col.has("nullable") || col.get("nullable").asBoolean();

            Object value = firstObject.get(columnName);

            // Check nullable constraint
            if (!nullable && value == null) {
                return new Handler.ValidationResult(false, "Column '" + columnName + "' cannot be null");
            }

            // Skip type checking for null values if column is nullable
            if (value == null && nullable) {
                continue;
            }

            // ClickHouse type validation
            Handler.ValidationResult result = validateClickHouseType(columnName, expectedType, value);
            if (!result.isValid()) {
                return result;
            }
        }

        return new Handler.ValidationResult(true, null);
    }

    private static Handler.ValidationResult validateClickHouseType(String columnName, String expectedType, Object value) {
        // Handle Nullable types
        if (expectedType.startsWith("Nullable(") && expectedType.endsWith(")")) {
            if (value == null) {
                return new Handler.ValidationResult(true, null);
            }
            // Extract inner type for non-null values
            String innerType = expectedType.substring(9, expectedType.length() - 1);
            return validateClickHouseType(columnName, innerType, value);
        }

        // Handle LowCardinality types
        if (expectedType.startsWith("LowCardinality(") && expectedType.endsWith(")")) {
            // Extract inner type
            String innerType = expectedType.substring(15, expectedType.length() - 1);
            return validateClickHouseType(columnName, innerType, value);
        }

        // Handle Array types
        if (expectedType.startsWith("Array(") && expectedType.endsWith(")")) {
            if (!(value instanceof List)) {
                return new Handler.ValidationResult(false, "Column '" + columnName + "' must be an array, got " + value.getClass().getSimpleName());
            }

            List<?> list = (List<?>) value;
            String innerType = expectedType.substring(6, expectedType.length() - 1);
            for (int i = 0; i < list.size(); i++) {
                Handler.ValidationResult result = validateClickHouseType(columnName + "[" + i + "]", innerType, list.get(i));
                if (!result.isValid()) {
                    return result;
                }
            }
            return new Handler.ValidationResult(true, null);
        }

        // Handle Enum8 types
        if (expectedType.startsWith("Enum8(") && expectedType.endsWith(")")) {
            if (!(value instanceof String)) {
                return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a string (enum value), got " + value.getClass().getSimpleName());
            }

            String enumPart = expectedType.substring(6, expectedType.length() - 1);
            Pattern enumPattern = Pattern.compile("'([^']+)'\\s*=\\s*\\d+");
            java.util.regex.Matcher matcher = enumPattern.matcher(enumPart);
            List<String> enumValues = new ArrayList<>();
            while (matcher.find()) {
                enumValues.add(matcher.group(1));
            }

            if (!enumValues.isEmpty() && !enumValues.contains(value.toString())) {
                return new Handler.ValidationResult(false, "Column '" + columnName + "' must be one of " + enumValues + ", got '" + value + "'");
            }
            return new Handler.ValidationResult(true, null);
        }

        // Handle Nested types
        if (expectedType.startsWith("Nested(") && expectedType.endsWith(")")) {
            if (!(value instanceof Map)) {
                return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a nested object (dict), got " + value.getClass().getSimpleName());
            }
            return new Handler.ValidationResult(true, null);
        }

        // Handle basic types
        switch (expectedType) {
            case "String":
                if (!(value instanceof String)) {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a string, got " + value.getClass().getSimpleName());
                }
                break;

            case "Int8":
            case "Int16":
            case "Int32":
            case "Int64":
            case "UInt8":
            case "UInt16":
            case "UInt32":
            case "UInt64":
                if (!(value instanceof Number)) {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be an integer, got " + value.getClass().getSimpleName());
                }

                long longValue = ((Number) value).longValue();
                Map<String, long[]> ranges = new HashMap<>();
                ranges.put("Int8", new long[]{-128, 127});
                ranges.put("Int16", new long[]{-32768, 32767});
                ranges.put("Int32", new long[]{-2147483648L, 2147483647L});
                ranges.put("Int64", new long[]{Long.MIN_VALUE, Long.MAX_VALUE});
                ranges.put("UInt8", new long[]{0, 255});
                ranges.put("UInt16", new long[]{0, 65535});
                ranges.put("UInt32", new long[]{0, 4294967295L});
                ranges.put("UInt64", new long[]{0, Long.MAX_VALUE});

                if (ranges.containsKey(expectedType)) {
                    long[] range = ranges.get(expectedType);
                    if (longValue < range[0] || longValue > range[1]) {
                        return new Handler.ValidationResult(false, 
                            "Column '" + columnName + "' value " + longValue + " is out of range for " + expectedType + " (" + range[0] + " to " + range[1] + ")");
                    }
                }
                break;

            case "Float32":
            case "Float64":
                if (!(value instanceof Number)) {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a number, got " + value.getClass().getSimpleName());
                }
                break;

            case "Bool":
                if (!(value instanceof Boolean)) {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a boolean, got " + value.getClass().getSimpleName());
                }
                break;

            case "DateTime":
                // Accept both time objects and ISO strings
                if (value instanceof String) {
                    String strValue = (String) value;
                    String isoPattern = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2})?$";
                    if (!Pattern.matches(isoPattern, strValue)) {
                        return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a valid ISO8601 datetime string, got '" + strValue + "'");
                    }

                    try {
                        Instant.parse(strValue);
                    } catch (DateTimeParseException e) {
                        return new Handler.ValidationResult(false, "Column '" + columnName + "' contains invalid datetime format: '" + strValue + "'");
                    }
                } else {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a datetime string, got " + value.getClass().getSimpleName());
                }
                break;

            case "Date":
            case "Date32":
                if (value instanceof String) {
                    String strValue = (String) value;
                    String datePattern = "^\\d{4}-\\d{2}-\\d{2}$";
                    if (!Pattern.matches(datePattern, strValue)) {
                        return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a valid date string (YYYY-MM-DD), got '" + strValue + "'");
                    }

                    try {
                        java.time.LocalDate.parse(strValue);
                    } catch (DateTimeParseException e) {
                        return new Handler.ValidationResult(false, "Column '" + columnName + "' contains invalid date: '" + strValue + "'");
                    }
                } else {
                    return new Handler.ValidationResult(false, "Column '" + columnName + "' must be a date string (YYYY-MM-DD), got " + value.getClass().getSimpleName());
                }
                break;

            default:
                // For unknown types, just log a warning but don't fail validation
                System.out.println("Warning: Unknown ClickHouse type '" + expectedType + "' for column '" + columnName + "', skipping type validation");
                break;
        }

        return new Handler.ValidationResult(true, null);
    }

    public static Handler.ValidationResult validateResponse(String functionType, IResponse responseData) {
        if (responseData.getStatusCode() == 200) {
            // Success responses - validate based on function type
            switch (functionType) {
                case "test-connection":
                    return validateTestConnectionResponse(responseData);
                case "access-scan":
                    return validateAccessScanResponse(responseData);
                case "get-object":
                    return validateGetObjectResponse(responseData);
                default:
                    return new Handler.ValidationResult(false, "Unknown function type: " + functionType);
            }
        } else {
            // Error responses - all function types use the same error format
            return validateErrorResponse(responseData);
        }
    }
}