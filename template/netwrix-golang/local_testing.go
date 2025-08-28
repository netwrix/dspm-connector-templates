package function

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ValidateRequestSchema(config map[string]interface{}, requestData map[string]interface{}, functionType string) (bool, string) {
	if requestData == nil {
		return false, "Request body must be a JSON object"
	}

	if functionType == "" {
		return false, "Missing FUNCTION_TYPE environment variable"
	}

	validFunctions := []string{"test-connection", "access-scan", "get-object"}
	isValidFunction := false
	for _, vf := range validFunctions {
		if functionType == vf {
			isValidFunction = true
			break
		}
	}
	if !isValidFunction {
		return false, fmt.Sprintf("Invalid function type. Must be one of: %v", validFunctions)
	}

	// Define allowed top-level properties for each function type
	allowedProperties := map[string][]string{
		"test-connection": {"connection"},
		"access-scan":     {"connection", "accessScan"},
		"get-object":      {"connection", "location"},
	}

	// Check for additional properties at the top level
	expectedProperties := allowedProperties[functionType]
	var extraProperties []string
	for key := range requestData {
		isAllowed := false
		for _, allowed := range expectedProperties {
			if key == allowed {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			extraProperties = append(extraProperties, key)
		}
	}
	if len(extraProperties) > 0 {
		return false, fmt.Sprintf("Additional properties not allowed for %s: %v", functionType, extraProperties)
	}

	// Validate connection object (required for all functions)
	connectionData, hasConnection := requestData["connection"]
	if !hasConnection {
		return false, "Missing required field: 'connection'"
	}

	connectionMap, ok := connectionData.(map[string]interface{})
	if !ok {
		return false, "'connection' must be an object"
	}

	// Validate connection fields against config.variables.connection
	variables, hasVariables := config["variables"]
	if hasVariables {
		variablesMap, ok := variables.(map[string]interface{})
		if ok {
			connectionConfig, hasConnectionConfig := variablesMap["connection"]
			if hasConnectionConfig {
				if connectionConfigList, ok := connectionConfig.([]interface{}); ok {
					isValid, errorMsg := validateObjectAgainstSchema(connectionMap, connectionConfigList, "connection")
					if !isValid {
						return false, errorMsg
					}
				}
			}
		}
	}

	// Function-specific validation
	if functionType == "access-scan" {
		accessScanData, hasAccessScan := requestData["accessScan"]
		if !hasAccessScan {
			return false, "Missing required field: 'accessScan' for access-scan function"
		}

		accessScanMap, ok := accessScanData.(map[string]interface{})
		if !ok {
			return false, "'accessScan' must be an object"
		}

		// Validate accessScan fields against config.variables.accessScan
		if hasVariables {
			variablesMap, ok := variables.(map[string]interface{})
			if ok {
				accessScanConfig, hasAccessScanConfig := variablesMap["accessScan"]
				if hasAccessScanConfig {
					if accessScanConfigList, ok := accessScanConfig.([]interface{}); ok {
						isValid, errorMsg := validateObjectAgainstSchema(accessScanMap, accessScanConfigList, "accessScan")
						if !isValid {
							return false, errorMsg
						}
					}
				}
			}
		}
	} else if functionType == "get-object" {
		locationData, hasLocation := requestData["location"]
		if !hasLocation {
			return false, "Missing required field: 'location' for get-object function"
		}

		locationMap, ok := locationData.(map[string]interface{})
		if !ok {
			return false, "'location' must be an object"
		}

		// Validate location fields against config.getObjectColumns
		getObjectColumns, hasGetObjectColumns := config["getObjectColumns"]
		if hasGetObjectColumns {
			if getObjectColumnsList, ok := getObjectColumns.([]interface{}); ok {
				isValid, errorMsg := validateLocationAgainstColumns(locationMap, getObjectColumnsList)
				if !isValid {
					return false, errorMsg
				}
			}
		}
	}

	return true, ""
}

func validateObjectAgainstSchema(data map[string]interface{}, schemaConfig []interface{}, fieldName string) (bool, string) {
	// Get list of allowed field keys from schema
	allowedKeys := make(map[string]bool)
	for _, fieldConfigInterface := range schemaConfig {
		if fieldConfigMap, ok := fieldConfigInterface.(map[string]interface{}); ok {
			if key, hasKey := fieldConfigMap["key"]; hasKey {
				if keyStr, ok := key.(string); ok {
					allowedKeys[keyStr] = true
				}
			}
		}
	}

	// Check for additional properties not in schema
	var extraKeys []string
	for key := range data {
		if !allowedKeys[key] {
			extraKeys = append(extraKeys, key)
		}
	}
	if len(extraKeys) > 0 {
		return false, fmt.Sprintf("Additional properties not allowed in '%s': %v", fieldName, extraKeys)
	}

	// Validate each field in schema
	for _, fieldConfigInterface := range schemaConfig {
		fieldConfigMap, ok := fieldConfigInterface.(map[string]interface{})
		if !ok {
			continue
		}

		fieldKey, hasKey := fieldConfigMap["key"].(string)
		if !hasKey {
			continue
		}

		fieldType, _ := fieldConfigMap["type"].(string)
		required, _ := fieldConfigMap["required"].(bool)

		value := data[fieldKey]

		// Check required fields
		if required && (value == nil || value == "") {
			return false, fmt.Sprintf("Missing required field: '%s.%s'", fieldName, fieldKey)
		}

		// Skip validation for optional fields that are not provided
		if value == nil && !required {
			continue
		}

		// Type validation
		if fieldType == "text" || fieldType == "string" {
			if _, ok := value.(string); !ok {
				return false, fmt.Sprintf("Field '%s.%s' must be a string, got %T", fieldName, fieldKey, value)
			}
		} else if fieldType == "number" {
			switch v := value.(type) {
			case int, int32, int64, float32, float64:
				// Check min/max constraints
				if minVal, hasMin := fieldConfigMap["min"]; hasMin {
					if minFloat, ok := minVal.(float64); ok {
						var valueFloat float64
						switch val := v.(type) {
						case int:
							valueFloat = float64(val)
						case int32:
							valueFloat = float64(val)
						case int64:
							valueFloat = float64(val)
						case float32:
							valueFloat = float64(val)
						case float64:
							valueFloat = val
						}
						if valueFloat < minFloat {
							return false, fmt.Sprintf("Field '%s.%s' must be >= %v, got %v", fieldName, fieldKey, minVal, value)
						}
					}
				}

				if maxVal, hasMax := fieldConfigMap["max"]; hasMax {
					if maxFloat, ok := maxVal.(float64); ok {
						var valueFloat float64
						switch val := v.(type) {
						case int:
							valueFloat = float64(val)
						case int32:
							valueFloat = float64(val)
						case int64:
							valueFloat = float64(val)
						case float32:
							valueFloat = float64(val)
						case float64:
							valueFloat = val
						}
						if valueFloat > maxFloat {
							return false, fmt.Sprintf("Field '%s.%s' must be <= %v, got %v", fieldName, fieldKey, maxVal, value)
						}
					}
				}
			default:
				return false, fmt.Sprintf("Field '%s.%s' must be a number, got %T", fieldName, fieldKey, value)
			}
		} else if fieldType == "checkbox" {
			if _, ok := value.(bool); !ok {
				return false, fmt.Sprintf("Field '%s.%s' must be a boolean, got %T", fieldName, fieldKey, value)
			}
		} else if fieldType == "list" {
			if value != nil {
				// For list fields, accept both arrays and single values
				var valueList []interface{}
				if str, ok := value.(string); ok {
					valueList = []interface{}{str}
				} else if list, ok := value.([]interface{}); ok {
					valueList = list
				} else {
					return false, fmt.Sprintf("Field '%s.%s' must be a string or array, got %T", fieldName, fieldKey, value)
				}

				// Validate options if specified
				if options, hasOptions := fieldConfigMap["options"]; hasOptions {
					if optionsList, ok := options.([]interface{}); ok {
						var validValues []string
						for _, opt := range optionsList {
							if optMap, ok := opt.(map[string]interface{}); ok {
								if val, hasVal := optMap["value"]; hasVal {
									if valStr, ok := val.(string); ok {
										validValues = append(validValues, valStr)
									}
								}
							}
						}

						if len(validValues) > 0 {
							for _, val := range valueList {
								if valStr, ok := val.(string); ok {
									isValid := false
									for _, validVal := range validValues {
										if valStr == validVal {
											isValid = true
											break
										}
									}
									if !isValid {
										return false, fmt.Sprintf("Field '%s.%s' contains invalid value '%s'. Valid options: %v", fieldName, fieldKey, valStr, validValues)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return true, ""
}

func validateLocationAgainstColumns(locationData map[string]interface{}, getObjectColumns []interface{}) (bool, string) {
	// Convert getObjectColumns to string slice
	var expectedColumns []string
	for _, col := range getObjectColumns {
		if colStr, ok := col.(string); ok {
			expectedColumns = append(expectedColumns, colStr)
		}
	}

	// Get actual columns in order
	var actualColumns []string
	for key := range locationData {
		actualColumns = append(actualColumns, key)
	}

	// Check that all expected columns are present and in the correct order
	if len(actualColumns) != len(expectedColumns) {
		return false, fmt.Sprintf("Location must contain exactly %d columns. Expected: %v, Got: %v", len(expectedColumns), expectedColumns, actualColumns)
	}

	// Check order and presence of columns
	for i, expectedCol := range expectedColumns {
		if i >= len(actualColumns) || actualColumns[i] != expectedCol {
			return false, fmt.Sprintf("Location columns must match order and names. Expected: %v, Got: %v", expectedColumns, actualColumns)
		}
	}

	// Validate that all values are strings (column values)
	for colName, colValue := range locationData {
		if _, ok := colValue.(string); !ok {
			return false, fmt.Sprintf("Location column '%s' must be a string, got %T", colName, colValue)
		}
	}

	return true, ""
}

func ValidateUpdateExecutionParams(status *string, totalObjects *int, completedObjects *int, incrementCompletedObjects *int, completedAt *string) (bool, string) {
	// Validate status
	if status != nil {
		validStatuses := []string{"running", "completed", "failed"}
		isValid := false
		for _, validStatus := range validStatuses {
			if *status == validStatus {
				isValid = true
				break
			}
		}
		if !isValid {
			return false, fmt.Sprintf("Invalid status: '%s'. Must be one of: %v", *status, validStatuses)
		}
	}

	// Validate total_objects
	if totalObjects != nil && *totalObjects < 0 {
		return false, fmt.Sprintf("total_objects must be a non-negative integer, got: %d", *totalObjects)
	}

	// Validate completed_objects
	if completedObjects != nil && *completedObjects < 0 {
		return false, fmt.Sprintf("completed_objects must be a non-negative integer, got: %d", *completedObjects)
	}

	// Validate increment_completed_objects
	if incrementCompletedObjects != nil && *incrementCompletedObjects < 0 {
		return false, fmt.Sprintf("increment_completed_objects must be a non-negative integer, got: %d", *incrementCompletedObjects)
	}

	// Check that only one of completed_objects or increment_completed_objects is provided
	if completedObjects != nil && incrementCompletedObjects != nil {
		return false, "Only one of completed_objects or increment_completed_objects can be provided, not both"
	}

	// Check that completed_objects is not greater than total_objects
	if totalObjects != nil && completedObjects != nil && *completedObjects > *totalObjects {
		return false, fmt.Sprintf("completed_objects (%d) cannot be greater than total_objects (%d)", *completedObjects, *totalObjects)
	}

	// Validate completed_at ISO8601 format
	if completedAt != nil {
		iso8601Pattern := `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$`
		matched, err := regexp.MatchString(iso8601Pattern, *completedAt)
		if err != nil || !matched {
			return false, fmt.Sprintf("completed_at must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '%s'", *completedAt)
		}

		// Additional validation by attempting to parse
		_, err = time.Parse(time.RFC3339, *completedAt)
		if err != nil {
			return false, fmt.Sprintf("completed_at is not a valid ISO8601 datetime: '%s'", *completedAt)
		}
	}

	return true, ""
}

func ValidateGetObjectResponse(responseData Response) (bool, string) {
	if responseData.Body == nil {
		return false, "Response must contain a 'body' property"
	}

	// Check that body contains only 'data' property
	hasData := false
	extraKeys := make([]string, 0)
	for key := range responseData.Body {
		if key == "data" {
			hasData = true
		} else {
			extraKeys = append(extraKeys, key)
		}
	}

	if len(extraKeys) > 0 {
		return false, fmt.Sprintf("Response body contains additional properties: %v", extraKeys)
	}

	if !hasData {
		return false, "Response body must contain a 'data' property"
	}

	dataValue := responseData.Body["data"]

	// Validate that data is a string
	dataStr, ok := dataValue.(string)
	if !ok {
		return false, fmt.Sprintf("Response body.data must be a string, got %T", dataValue)
	}

	// Validate that data is not empty
	if dataStr == "" {
		return false, "Response body.data cannot be empty"
	}

	// Check base64 format using regex
	base64Pattern := `^[A-Za-z0-9+/]*={0,2}$`
	matched, err := regexp.MatchString(base64Pattern, dataStr)
	if err != nil || !matched {
		return false, "Response body.data is not valid base64 format"
	}

	// Try to decode to verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return false, "Response body.data is not valid base64 encoding"
	}

	return true, ""
}

func ValidateTestConnectionResponse(responseData Response) (bool, string) {
	if responseData.Body == nil {
		return false, "Response must contain a 'body' property"
	}

	// Check that body contains only required properties
	requiredKeys := map[string]bool{"startedAt": true, "completedAt": true}
	extraKeys := make([]string, 0)
	missingKeys := make([]string, 0)

	for key := range requiredKeys {
		if _, exists := responseData.Body[key]; !exists {
			missingKeys = append(missingKeys, key)
		}
	}

	for key := range responseData.Body {
		if !requiredKeys[key] {
			extraKeys = append(extraKeys, key)
		}
	}

	if len(missingKeys) > 0 {
		return false, fmt.Sprintf("Response body missing required properties: %v", missingKeys)
	}

	if len(extraKeys) > 0 {
		return false, fmt.Sprintf("Response body contains additional properties: %v", extraKeys)
	}

	// Validate datetime formats (ISO8601)
	iso8601Pattern := `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$`

	for _, fieldName := range []string{"startedAt", "completedAt"} {
		fieldValue := responseData.Body[fieldName]

		// Validate that field is a string
		fieldStr, ok := fieldValue.(string)
		if !ok {
			return false, fmt.Sprintf("Response body.%s must be a string, got %T", fieldName, fieldValue)
		}

		// Validate ISO8601 format
		matched, err := regexp.MatchString(iso8601Pattern, fieldStr)
		if err != nil || !matched {
			return false, fmt.Sprintf("Response body.%s must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '%s'", fieldName, fieldStr)
		}

		// Additional validation by attempting to parse
		_, err = time.Parse(time.RFC3339, fieldStr)
		if err != nil {
			return false, fmt.Sprintf("Response body.%s is not a valid ISO8601 datetime: '%s'", fieldName, fieldStr)
		}
	}

	// Validate that completedAt is after startedAt
	startedAtStr := responseData.Body["startedAt"].(string)
	completedAtStr := responseData.Body["completedAt"].(string)

	startedAt, err1 := time.Parse(time.RFC3339, startedAtStr)
	completedAt, err2 := time.Parse(time.RFC3339, completedAtStr)

	if err1 == nil && err2 == nil && completedAt.Before(startedAt) {
		return false, fmt.Sprintf("Response body.completedAt (%s) must be after startedAt (%s)", completedAtStr, startedAtStr)
	}

	return true, ""
}

func ValidateAccessScanResponse(responseData Response) (bool, string) {
	// Access scan response has the same validation as test connection
	return ValidateTestConnectionResponse(responseData)
}

func ValidateErrorResponse(responseData Response) (bool, string) {
	if responseData.Body == nil {
		return false, "Response must contain a 'body' property"
	}

	// Check that body contains only the required property
	hasError := false
	extraKeys := make([]string, 0)
	for key := range responseData.Body {
		if key == "error" {
			hasError = true
		} else {
			extraKeys = append(extraKeys, key)
		}
	}

	if !hasError {
		return false, "Response body missing required properties: [error]"
	}

	if len(extraKeys) > 0 {
		return false, fmt.Sprintf("Response body contains additional properties: %v", extraKeys)
	}

	// Validate error field
	errorMessage := responseData.Body["error"]

	// Validate that error is a string
	errorStr, ok := errorMessage.(string)
	if !ok {
		return false, fmt.Sprintf("Response body.error must be a string, got %T", errorMessage)
	}

	// Validate that error is not empty
	if strings.TrimSpace(errorStr) == "" {
		return false, "Response body.error cannot be empty"
	}

	return true, ""
}

func ValidateDevData(config map[string]interface{}, data []map[string]interface{}) (bool, string) {
	// Intelligence is now an array of columns, table name is always 'access'
	intelligence, hasIntelligence := config["intelligence"]
	if !hasIntelligence {
		return false, "No columns found in config.intelligence"
	}

	tableColumns, ok := intelligence.([]interface{})
	if !ok {
		return false, "config.intelligence must be an array"
	}

	if len(tableColumns) == 0 {
		return false, "No columns found in config.intelligence"
	}

	// Validate data is an array of objects
	if len(data) == 0 {
		return false, "Data array cannot be empty"
	}

	// Validate first object matches expected columns and data types
	firstObject := data[0]

	// The actual data will have scan_id, scan_execution_id, and scanned_at added by save_data
	expectedTrackingFields := []string{"scan_id", "scan_execution_id", "scanned_at"}
	var expectedColumnNames []string
	expectedColumnNames = append(expectedColumnNames, expectedTrackingFields...)

	for _, col := range tableColumns {
		if colMap, ok := col.(map[string]interface{}); ok {
			if name, hasName := colMap["name"].(string); hasName {
				expectedColumnNames = append(expectedColumnNames, name)
			}
		}
	}

	var actualColumns []string
	for key := range firstObject {
		actualColumns = append(actualColumns, key)
	}

	// Check column names match and are in the same order
	if len(actualColumns) != len(expectedColumnNames) {
		return false, fmt.Sprintf("Column names/order mismatch. Expected: %v, Got: %v", expectedColumnNames, actualColumns)
	}

	for i, expected := range expectedColumnNames {
		if i >= len(actualColumns) || actualColumns[i] != expected {
			return false, fmt.Sprintf("Column names/order mismatch. Expected: %v, Got: %v", expectedColumnNames, actualColumns)
		}
	}

	// Validate tracking fields first
	trackingFieldTypes := map[string]string{
		"scan_id":           "LowCardinality(String)",
		"scan_execution_id": "LowCardinality(String)",
		"scanned_at":        "DateTime",
	}

	for fieldName, fieldType := range trackingFieldTypes {
		value := firstObject[fieldName]
		if value == nil {
			return false, fmt.Sprintf("Required tracking field '%s' is missing", fieldName)
		}

		isValid, typeError := validateClickHouseType(fieldName, fieldType, value)
		if !isValid {
			return false, typeError
		}
	}

	// Validate data types for each column from intelligence config
	for _, col := range tableColumns {
		colMap, ok := col.(map[string]interface{})
		if !ok {
			continue
		}

		columnName, hasName := colMap["name"].(string)
		if !hasName {
			continue
		}

		expectedType, hasType := colMap["type"].(string)
		if !hasType {
			continue
		}

		nullable, _ := colMap["nullable"].(bool)
		if colMap["nullable"] == nil {
			nullable = true // Default to true
		}

		value := firstObject[columnName]

		// Check nullable constraint
		if !nullable && value == nil {
			return false, fmt.Sprintf("Column '%s' cannot be null", columnName)
		}

		// Skip type checking for null values if column is nullable
		if value == nil && nullable {
			continue
		}

		// ClickHouse type validation
		isValid, typeError := validateClickHouseType(columnName, expectedType, value)
		if !isValid {
			return false, typeError
		}
	}

	return true, ""
}

func validateClickHouseType(columnName, expectedType string, value interface{}) (bool, string) {
	// Handle Nullable types
	if strings.HasPrefix(expectedType, "Nullable(") && strings.HasSuffix(expectedType, ")") {
		if value == nil {
			return true, ""
		}
		// Extract inner type for non-null values
		innerType := expectedType[9 : len(expectedType)-1] // Remove 'Nullable(' and ')'
		return validateClickHouseType(columnName, innerType, value)
	}

	// Handle LowCardinality types
	if strings.HasPrefix(expectedType, "LowCardinality(") && strings.HasSuffix(expectedType, ")") {
		// Extract inner type
		innerType := expectedType[15 : len(expectedType)-1] // Remove 'LowCardinality(' and ')'
		return validateClickHouseType(columnName, innerType, value)
	}

	// Handle Array types
	if strings.HasPrefix(expectedType, "Array(") && strings.HasSuffix(expectedType, ")") {
		slice, ok := value.([]interface{})
		if !ok {
			return false, fmt.Sprintf("Column '%s' must be an array, got %T", columnName, value)
		}

		// Extract inner type and validate each element
		innerType := expectedType[6 : len(expectedType)-1] // Remove 'Array(' and ')'
		for i, item := range slice {
			isValid, err := validateClickHouseType(fmt.Sprintf("%s[%d]", columnName, i), innerType, item)
			if !isValid {
				return false, err
			}
		}
		return true, ""
	}

	// Handle Enum8 types
	if strings.HasPrefix(expectedType, "Enum8(") && strings.HasSuffix(expectedType, ")") {
		valueStr, ok := value.(string)
		if !ok {
			return false, fmt.Sprintf("Column '%s' must be a string (enum value), got %T", columnName, value)
		}

		// Extract enum values from the type definition
		enumPart := expectedType[6 : len(expectedType)-1] // Remove 'Enum8(' and ')'
		// Parse enum values like 'SUCCESS' = 1, 'ERROR' = 2
		enumPattern := `'([^']+)'\s*=\s*\d+`
		re := regexp.MustCompile(enumPattern)
		matches := re.FindAllStringSubmatch(enumPart, -1)

		var enumValues []string
		for _, match := range matches {
			if len(match) > 1 {
				enumValues = append(enumValues, match[1])
			}
		}

		if len(enumValues) > 0 {
			isValid := false
			for _, enumValue := range enumValues {
				if valueStr == enumValue {
					isValid = true
					break
				}
			}
			if !isValid {
				return false, fmt.Sprintf("Column '%s' must be one of %v, got '%s'", columnName, enumValues, valueStr)
			}
		}
		return true, ""
	}

	// Handle Nested types
	if strings.HasPrefix(expectedType, "Nested(") && strings.HasSuffix(expectedType, ")") {
		_, ok := value.(map[string]interface{})
		if !ok {
			return false, fmt.Sprintf("Column '%s' must be a nested object (dict), got %T", columnName, value)
		}
		// Simplified validation for nested types
		return true, ""
	}

	// Handle basic types
	switch expectedType {
	case "String":
		if _, ok := value.(string); !ok {
			return false, fmt.Sprintf("Column '%s' must be a string, got %T", columnName, value)
		}

	case "Int8", "Int16", "Int32", "Int64", "UInt8", "UInt16", "UInt32", "UInt64":
		var intValue int64
		switch v := value.(type) {
		case int:
			intValue = int64(v)
		case int32:
			intValue = int64(v)
		case int64:
			intValue = v
		case float64:
			intValue = int64(v)
		default:
			return false, fmt.Sprintf("Column '%s' must be an integer, got %T", columnName, value)
		}

		// Validate integer ranges
		ranges := map[string][2]int64{
			"Int8":   {-128, 127},
			"Int16":  {-32768, 32767},
			"Int32":  {-2147483648, 2147483647},
			"Int64":  {-9223372036854775808, 9223372036854775807},
			"UInt8":  {0, 255},
			"UInt16": {0, 65535},
			"UInt32": {0, 4294967295},
			"UInt64": {0, 9223372036854775807}, // Go int64 max for simplicity
		}

		if r, exists := ranges[expectedType]; exists {
			if intValue < r[0] || intValue > r[1] {
				return false, fmt.Sprintf("Column '%s' value %d is out of range for %s (%d to %d)", columnName, intValue, expectedType, r[0], r[1])
			}
		}

	case "Float32", "Float64":
		switch value.(type) {
		case int, int32, int64, float32, float64:
			// Valid numeric types
		default:
			return false, fmt.Sprintf("Column '%s' must be a number, got %T", columnName, value)
		}

	case "Bool":
		if _, ok := value.(bool); !ok {
			return false, fmt.Sprintf("Column '%s' must be a boolean, got %T", columnName, value)
		}

	case "DateTime":
		// Accept both time objects and ISO strings
		if timeValue, ok := value.(time.Time); ok {
			_ = timeValue // Valid
		} else if strValue, ok := value.(string); ok {
			// Validate ISO8601 format
			isoPattern := `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$`
			matched, err := regexp.MatchString(isoPattern, strValue)
			if err != nil || !matched {
				return false, fmt.Sprintf("Column '%s' must be a valid ISO8601 datetime string, got '%s'", columnName, strValue)
			}

			// Try to parse to validate
			_, err = time.Parse(time.RFC3339, strValue)
			if err != nil {
				return false, fmt.Sprintf("Column '%s' contains invalid datetime format: '%s'", columnName, strValue)
			}
		} else {
			return false, fmt.Sprintf("Column '%s' must be a datetime object or ISO8601 string, got %T", columnName, value)
		}

	case "Date", "Date32":
		if strValue, ok := value.(string); ok {
			// Validate date format YYYY-MM-DD
			datePattern := `^\d{4}-\d{2}-\d{2}$`
			matched, err := regexp.MatchString(datePattern, strValue)
			if err != nil || !matched {
				return false, fmt.Sprintf("Column '%s' must be a valid date string (YYYY-MM-DD), got '%s'", columnName, strValue)
			}

			_, err = time.Parse("2006-01-02", strValue)
			if err != nil {
				return false, fmt.Sprintf("Column '%s' contains invalid date: '%s'", columnName, strValue)
			}
		} else {
			return false, fmt.Sprintf("Column '%s' must be a date string (YYYY-MM-DD), got %T", columnName, value)
		}

	default:
		// For unknown types, just log a warning but don't fail validation
		fmt.Printf("Warning: Unknown ClickHouse type '%s' for column '%s', skipping type validation\n", expectedType, columnName)
	}

	return true, ""
}

func ValidateResponse(functionType string, responseData Response) (bool, string) {
	if responseData.StatusCode == 200 {
		// Success responses - validate based on function type
		switch functionType {
		case "test-connection":
			return ValidateTestConnectionResponse(responseData)
		case "access-scan":
			return ValidateAccessScanResponse(responseData)
		case "get-object":
			return ValidateGetObjectResponse(responseData)
		default:
			return false, fmt.Sprintf("Unknown function type: %s", functionType)
		}
	} else {
		// Error responses - all function types use the same error format
		return ValidateErrorResponse(responseData)
	}
}