package function

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	Body    []byte              `json:"body"`
	Headers map[string][]string `json:"headers"`
	Method  string              `json:"method"`
	Query   map[string][]string `json:"query"`
	Path    string              `json:"path"`
}

type Context struct {
	Hostname          string                 `json:"hostname"`
	Secrets           map[string]string      `json:"secrets"`
	ScanID            string                 `json:"scan_id"`
	SyncID            string                 `json:"sync_id"`
	ScanExecutionID   string                 `json:"scan_execution_id"`
	SyncExecutionID   string                 `json:"sync_execution_id"`
	RunLocal          string                 `json:"run_local"`
	Config            map[string]interface{} `json:"config"`
	FunctionType      string                 `json:"function_type"`
}

type ResponseBody struct {
	Error       string      `json:"error,omitempty"`
	Data        string      `json:"data,omitempty"`
	StartedAt   string      `json:"startedAt,omitempty"`
	CompletedAt string      `json:"completedAt,omitempty"`
}

type Response struct {
	StatusCode int                    `json:"statusCode"`
	Body       map[string]interface{} `json:"body"`
	Headers    map[string]string      `json:"headers,omitempty"`
}

func (c *Context) TestConnectionSuccessResponse() Response {
	return Response{
		StatusCode: 200,
		Body:       map[string]interface{}{},
	}
}

func (c *Context) AccessScanSuccessResponse() Response {
	return Response{
		StatusCode: 200,
		Body:       map[string]interface{}{},
	}
}

func (c *Context) GetObjectSuccessResponse(data []byte) Response {
	encodedData := base64.StdEncoding.EncodeToString(data)
	return Response{
		StatusCode: 200,
		Body: map[string]interface{}{
			"data": encodedData,
		},
	}
}

func (c *Context) ErrorResponse(clientError bool, errorMsg string) Response {
	statusCode := 500
	if clientError {
		statusCode = 400
	}

	return Response{
		StatusCode: statusCode,
		Body: map[string]interface{}{
			"error": errorMsg,
		},
	}
}

func (c *Context) SaveData(data []interface{}) (bool, string) {
	// Add scan_id, scan_execution_id, and scanned_at to each row
	var enhancedData []map[string]interface{}
	currentTime := time.Now().UTC().Format(time.RFC3339)

	localRun := c.RunLocal == "true"
	scanID := "scan0001"
	scanExecutionID := "scan-0002"
	
	if !localRun {
		scanID = c.ScanID
		scanExecutionID = c.ScanExecutionID
	}

	for _, row := range data {
		if rowMap, ok := row.(map[string]interface{}); ok {
			enhancedRow := map[string]interface{}{
				"scan_id":           scanID,
				"scan_execution_id": scanExecutionID,
				"scanned_at":        currentTime,
			}
			// Merge original row data
			for k, v := range rowMap {
				enhancedRow[k] = v
			}
			enhancedData = append(enhancedData, enhancedRow)
		}
	}

	// Dev environment validation
	if localRun {
		isValid, errorMsg := ValidateDevData(c.Config, enhancedData)
		if !isValid {
			log.Println(errorMsg)
			return false, errorMsg
		} else {
			log.Printf("Saving %d items to table\n", len(enhancedData))
			if len(enhancedData) > 0 {
				sampleJSON, _ := json.MarshalIndent(enhancedData[0], "", "  ")
				log.Printf("Sample item: %s\n", string(sampleJSON))
			}
			return true, ""
		}
	} else {
		saveDataFunction := os.Getenv("SAVE_DATA_FUNCTION")
		if saveDataFunction == "" {
			errorMsg := "SAVE_DATA_FUNCTION is not in the environment"
			log.Println(errorMsg)
			return false, errorMsg
		}

		payload := map[string]interface{}{
			"sourceType": os.Getenv("SOURCE_TYPE"),
			"version":    os.Getenv("SOURCE_VERSION"),
			"table":      "access",
			"data":       enhancedData,
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			errorMsg := fmt.Sprintf("Error marshaling payload: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}

		url := fmt.Sprintf("%s/async-function/%s", os.Getenv("OPENFAAS_GATEWAY"), saveDataFunction)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
		if err != nil {
			errorMsg := fmt.Sprintf("Error creating request: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}

		req.Header.Set("Content-Type", "application/json")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			errorMsg := fmt.Sprintf("Error: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}
		defer resp.Body.Close()

		if resp.StatusCode == 202 {
			return true, ""
		} else {
			body, _ := io.ReadAll(resp.Body)
			errorMsg := fmt.Sprintf("Status %d: %s", resp.StatusCode, string(body))
			log.Println(errorMsg)
			return false, errorMsg
		}
	}
}

func (c *Context) UpdateExecution(status *string, totalObjects *int, completedObjects *int, incrementCompletedObjects *int, completedAt *string) (bool, string) {
	// Validation for dev environment
	if c.RunLocal == "true" {
		isValid, errorMsg := ValidateUpdateExecutionParams(status, totalObjects, completedObjects, incrementCompletedObjects, completedAt)
		if !isValid {
			log.Println(errorMsg)
			return false, errorMsg
		} else {
			return true, ""
		}
	} else {
		appUpdateFunction := os.Getenv("APP_UPDATE_EXECUTION_FUNCTION")
		if appUpdateFunction == "" {
			errorMsg := "APP_UPDATE_EXECUTION_FUNCTION is not in the environment"
			log.Println(errorMsg)
			return false, errorMsg
		}

		var executionID string
		var executionType string

		if c.ScanExecutionID != "" {
			executionID = c.ScanExecutionID
			executionType = "scan"
		} else if c.SyncExecutionID != "" {
			executionID = c.SyncExecutionID
			executionType = "sync"
		} else {
			errorMsg := "Missing required field: either 'scanExecutionId' or 'syncExecutionId' must be provided"
			log.Println(errorMsg)
			return false, errorMsg
		}

		payload := map[string]interface{}{
			"type":        executionType,
			"executionId": executionID,
		}

		// Only include optional fields if they are provided (not nil)
		if status != nil {
			payload["status"] = *status
		}
		if totalObjects != nil {
			payload["totalObjects"] = *totalObjects
		}
		if completedObjects != nil {
			payload["completedObjects"] = *completedObjects
		}
		if incrementCompletedObjects != nil {
			payload["incrementCompletedObjects"] = *incrementCompletedObjects
		}
		if completedAt != nil {
			payload["completedAt"] = *completedAt
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			errorMsg := fmt.Sprintf("Error marshaling payload: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}

		url := fmt.Sprintf("%s/async-function/%s", os.Getenv("OPENFAAS_GATEWAY"), appUpdateFunction)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
		if err != nil {
			errorMsg := fmt.Sprintf("Error creating request: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}

		req.Header.Set("Content-Type", "application/json")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			errorMsg := fmt.Sprintf("Error: %v", err)
			log.Println(errorMsg)
			return false, errorMsg
		}
		defer resp.Body.Close()

		if resp.StatusCode == 202 {
			return true, ""
		} else {
			body, _ := io.ReadAll(resp.Body)
			errorMsg := fmt.Sprintf("Status %d: %s", resp.StatusCode, string(body))
			log.Println(errorMsg)
			return false, errorMsg
		}
	}
}

func getSecrets(localRun bool) map[string]string {
	secrets := make(map[string]string)
	secretsDir := "/var/openfaas/secrets/"

	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		log.Printf("Error reading secrets directory: %v\n", err)
		return secrets
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		secretPath := filepath.Join(secretsDir, filename)

		var keyName string
		if localRun {
			// For local run, use the filename as-is (no scan ID removal)
			keyName = filename
		} else {
			// For non-local run, remove the last 9 characters (dash + 8 chars scan ID)
			if len(filename) > 9 && filename[len(filename)-9:len(filename)-8] == "-" {
				keyName = filename[:len(filename)-9] // Remove last 9 characters (-abcd1234)
			} else {
				log.Printf("Skipping secret file with unexpected format: %s\n", filename)
				continue
			}
		}

		// Convert dash-separated to camelCase
		keyParts := strings.Split(keyName, "-")
		var camelKey string
		if len(keyParts) > 1 {
			// First part stays lowercase, subsequent parts are capitalized
			camelKey = keyParts[0]
			for _, part := range keyParts[1:] {
				camelKey += strings.Title(part)
			}
		} else {
			camelKey = keyParts[0]
		}

		// Read the secret content
		content, err := os.ReadFile(secretPath)
		if err != nil {
			log.Printf("Error reading secret file %s: %v\n", filename, err)
		} else {
			secrets[camelKey] = strings.TrimSpace(string(content))
			log.Printf("Loaded secret: %s\n", camelKey)
		}
	}

	return secrets
}

func Handle(w http.ResponseWriter, r *http.Request) {
	event := Event{
		Body:    nil,
		Headers: r.Header,
		Method:  r.Method,
		Query:   r.URL.Query(),
		Path:    r.URL.Path,
	}

	if r.Body != nil {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		event.Body = body
	}

	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		hostname = "localhost"
	}

	context := Context{
		Hostname:     hostname,
		ScanID:       os.Getenv("SCAN_ID"),
		SyncID:       os.Getenv("SYNC_ID"),
		RunLocal:     os.Getenv("RUN_LOCAL"),
		FunctionType: os.Getenv("FUNCTION_TYPE"),
	}

	if context.RunLocal == "" {
		context.RunLocal = "false"
	}

	// Parse CONFIG
	configStr := os.Getenv("CONFIG")
	if configStr != "" {
		err := json.Unmarshal([]byte(configStr), &context.Config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON in CONFIG: %v", err), http.StatusBadRequest)
			return
		}
	}

	localRun := context.RunLocal == "true"

	if localRun {
		if context.Config == nil {
			http.Error(w, "CONFIG is required when RUN_LOCAL is true", http.StatusBadRequest)
			return
		}

		if context.FunctionType == "" {
			http.Error(w, "FUNCTION_TYPE is required when RUN_LOCAL is true", http.StatusBadRequest)
			return
		}

		// Validate request body against config
		var requestData map[string]interface{}
		if len(event.Body) > 0 {
			err := json.Unmarshal(event.Body, &requestData)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid JSON in request body: %v", err), http.StatusBadRequest)
				return
			}

			isValid, errorMsg := ValidateRequestSchema(context.Config, requestData, context.FunctionType)
			if !isValid {
				http.Error(w, errorMsg, http.StatusBadRequest)
				return
			}
		}
	}

	// Load secrets from OpenFaaS secret files
	context.Secrets = getSecrets(localRun)

	// Parse execution IDs from request body
	if len(event.Body) > 0 {
		var requestData map[string]interface{}
		json.Unmarshal(event.Body, &requestData)
		if scanExecutionID, ok := requestData["scanExecutionId"].(string); ok {
			context.ScanExecutionID = scanExecutionID
		}
		if syncExecutionID, ok := requestData["syncExecutionId"].(string); ok {
			context.SyncExecutionID = syncExecutionID
		}
	}

	if len(context.Secrets) == 0 {
		log.Println("Warning: No secrets loaded from secret files")
	} else {
		log.Printf("Loaded %d secrets from secret files\n", len(context.Secrets))
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)
	responseData := handleFunction(event, context)
	completedAt := time.Now().UTC().Format(time.RFC3339)

	responseJSON, _ := json.Marshal(responseData)
	log.Printf("Response data: %s\n", string(responseJSON))

	// Add timestamps for successful responses
	if context.FunctionType == "test-connection" && responseData.StatusCode == 200 {
		if responseData.Body == nil {
			responseData.Body = make(map[string]interface{})
		}
		responseData.Body["startedAt"] = startedAt
		responseData.Body["completedAt"] = completedAt
	} else if context.FunctionType == "access-scan" && responseData.StatusCode == 200 {
		if responseData.Body == nil {
			responseData.Body = make(map[string]interface{})
		}
		responseData.Body["startedAt"] = startedAt
		responseData.Body["completedAt"] = completedAt
	}

	if localRun {
		isValid, errorMsg := ValidateResponse(context.FunctionType, responseData)
		if !isValid {
			responseData = context.ErrorResponse(false, errorMsg)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseData.StatusCode)

	if responseData.Body != nil {
		json.NewEncoder(w).Encode(responseData.Body)
	}
}

// handleFunction is a placeholder for the actual function implementation
func handleFunction(event Event, context Context) Response {
	// This would call the actual handler implementation
	// For now, return a simple response
	return Response{
		StatusCode: 200,
		Body:       map[string]interface{}{"message": "Hello from Netwrix Go handler"},
	}
}