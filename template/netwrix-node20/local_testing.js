function validateRequestSchema(config, requestData, functionType) {
    if (!requestData || typeof requestData !== 'object') {
        return { isValid: false, errorMsg: "Request body must be a JSON object" };
    }

    if (!functionType) {
        return { isValid: false, errorMsg: "Missing FUNCTION_TYPE environment variable" };
    }

    const validFunctions = ['test-connection', 'access-scan', 'get-object'];
    if (!validFunctions.includes(functionType)) {
        return { isValid: false, errorMsg: `Invalid function type. Must be one of: ${validFunctions}` };
    }

    // Define allowed top-level properties for each function type
    const allowedProperties = {
        'test-connection': ['connection'],
        'access-scan': ['connection', 'accessScan'],
        'get-object': ['connection', 'location']
    };

    // Check for additional properties at the top level
    const actualProperties = Object.keys(requestData);
    const expectedProperties = allowedProperties[functionType];
    const extraProperties = actualProperties.filter(prop => !expectedProperties.includes(prop));
    if (extraProperties.length > 0) {
        return { isValid: false, errorMsg: `Additional properties not allowed for ${functionType}: ${extraProperties.sort()}` };
    }

    // Validate connection object (required for all functions)
    if (!requestData.connection) {
        return { isValid: false, errorMsg: "Missing required field: 'connection'" };
    }

    if (typeof requestData.connection !== 'object') {
        return { isValid: false, errorMsg: "'connection' must be an object" };
    }

    // Validate connection fields against config.variables.connection
    if (config.variables && config.variables.connection) {
        const result = validateObjectAgainstSchema(requestData.connection, config.variables.connection, 'connection');
        if (!result.isValid) {
            return result;
        }
    }

    // Function-specific validation
    if (functionType === 'access-scan') {
        if (!requestData.accessScan) {
            return { isValid: false, errorMsg: "Missing required field: 'accessScan' for access-scan function" };
        }

        if (typeof requestData.accessScan !== 'object') {
            return { isValid: false, errorMsg: "'accessScan' must be an object" };
        }

        // Validate accessScan fields against config.variables.accessScan
        if (config.variables && config.variables.accessScan) {
            const result = validateObjectAgainstSchema(requestData.accessScan, config.variables.accessScan, 'accessScan');
            if (!result.isValid) {
                return result;
            }
        }
    } else if (functionType === 'get-object') {
        if (!requestData.location) {
            return { isValid: false, errorMsg: "Missing required field: 'location' for get-object function" };
        }

        if (typeof requestData.location !== 'object') {
            return { isValid: false, errorMsg: "'location' must be an object" };
        }

        // Validate location fields against config.getObjectColumns
        if (config.getObjectColumns) {
            const result = validateLocationAgainstColumns(requestData.location, config.getObjectColumns);
            if (!result.isValid) {
                return result;
            }
        }
    }

    return { isValid: true, errorMsg: null };
}

function validateObjectAgainstSchema(data, schemaConfig, fieldName) {
    // Get list of allowed field keys from schema
    const allowedKeys = new Set();
    for (const fieldConfig of schemaConfig) {
        if (fieldConfig.key) {
            allowedKeys.add(fieldConfig.key);
        }
    }

    // Check for additional properties not in schema
    const actualKeys = Object.keys(data);
    const extraKeys = actualKeys.filter(key => !allowedKeys.has(key));
    if (extraKeys.length > 0) {
        return { isValid: false, errorMsg: `Additional properties not allowed in '${fieldName}': ${extraKeys.sort()}` };
    }

    // Validate each field in schema
    for (const fieldConfig of schemaConfig) {
        const fieldKey = fieldConfig.key;
        const fieldType = fieldConfig.type;
        const required = fieldConfig.required || false;

        const value = data[fieldKey];

        // Check required fields
        if (required && (value === null || value === undefined || value === "")) {
            return { isValid: false, errorMsg: `Missing required field: '${fieldName}.${fieldKey}'` };
        }

        // Skip validation for optional fields that are not provided
        if ((value === null || value === undefined) && !required) {
            continue;
        }

        // Type validation
        if (fieldType === 'text' || fieldType === 'string') {
            if (typeof value !== 'string') {
                return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be a string, got ${typeof value}` };
            }
        } else if (fieldType === 'number') {
            if (typeof value !== 'number') {
                return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be a number, got ${typeof value}` };
            }

            // Check min/max constraints
            if (fieldConfig.min !== undefined && value < fieldConfig.min) {
                return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be >= ${fieldConfig.min}, got ${value}` };
            }
            if (fieldConfig.max !== undefined && value > fieldConfig.max) {
                return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be <= ${fieldConfig.max}, got ${value}` };
            }
        } else if (fieldType === 'checkbox') {
            if (typeof value !== 'boolean') {
                return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be a boolean, got ${typeof value}` };
            }
        } else if (fieldType === 'list') {
            if (value !== null && value !== undefined) {
                // For list fields, accept both arrays and single values
                let valueList;
                if (typeof value === 'string') {
                    valueList = [value];
                } else if (Array.isArray(value)) {
                    valueList = value;
                } else {
                    return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' must be a string or array, got ${typeof value}` };
                }

                // Validate options if specified
                if (fieldConfig.options && fieldConfig.options.length > 0) {
                    const validValues = fieldConfig.options.map(opt => opt.value).filter(v => v !== undefined);
                    for (const val of valueList) {
                        if (!validValues.includes(val)) {
                            return { isValid: false, errorMsg: `Field '${fieldName}.${fieldKey}' contains invalid value '${val}'. Valid options: ${validValues}` };
                        }
                    }
                }
            }
        }
    }

    return { isValid: true, errorMsg: null };
}

function validateLocationAgainstColumns(locationData, getObjectColumns) {
    const expectedColumns = getObjectColumns;
    const actualColumns = Object.keys(locationData);

    // Check that all expected columns are present and in the correct order
    if (actualColumns.length !== expectedColumns.length) {
        return { isValid: false, errorMsg: `Location must contain exactly ${expectedColumns.length} columns. Expected: ${expectedColumns}, Got: ${actualColumns}` };
    }

    // Check order and presence of columns
    for (let i = 0; i < expectedColumns.length; i++) {
        if (i >= actualColumns.length || actualColumns[i] !== expectedColumns[i]) {
            return { isValid: false, errorMsg: `Location columns must match order and names. Expected: ${expectedColumns}, Got: ${actualColumns}` };
        }
    }

    // Validate that all values are strings (column values)
    for (const [colName, colValue] of Object.entries(locationData)) {
        if (typeof colValue !== 'string') {
            return { isValid: false, errorMsg: `Location column '${colName}' must be a string, got ${typeof colValue}` };
        }
    }

    return { isValid: true, errorMsg: null };
}

function validateUpdateExecutionParams(status, totalObjects, completedObjects, incrementCompletedObjects, completedAt) {
    // Validate status
    if (status !== null && status !== undefined) {
        const validStatuses = ["running", "completed", "failed"];
        if (!validStatuses.includes(status)) {
            return { isValid: false, errorMsg: `Invalid status: '${status}'. Must be one of: ${validStatuses}` };
        }
    }

    // Validate total_objects
    if (totalObjects !== null && totalObjects !== undefined) {
        if (!Number.isInteger(totalObjects) || totalObjects < 0) {
            return { isValid: false, errorMsg: `total_objects must be a non-negative integer, got: ${totalObjects}` };
        }
    }

    // Validate completed_objects
    if (completedObjects !== null && completedObjects !== undefined) {
        if (!Number.isInteger(completedObjects) || completedObjects < 0) {
            return { isValid: false, errorMsg: `completed_objects must be a non-negative integer, got: ${completedObjects}` };
        }
    }

    // Validate increment_completed_objects
    if (incrementCompletedObjects !== null && incrementCompletedObjects !== undefined) {
        if (!Number.isInteger(incrementCompletedObjects) || incrementCompletedObjects < 0) {
            return { isValid: false, errorMsg: `increment_completed_objects must be a non-negative integer, got: ${incrementCompletedObjects}` };
        }
    }

    // Check that only one of completed_objects or increment_completed_objects is provided
    if (completedObjects !== null && completedObjects !== undefined && 
        incrementCompletedObjects !== null && incrementCompletedObjects !== undefined) {
        return { isValid: false, errorMsg: "Only one of completed_objects or increment_completed_objects can be provided, not both" };
    }

    // Check that completed_objects is not greater than total_objects
    if (totalObjects !== null && totalObjects !== undefined && 
        completedObjects !== null && completedObjects !== undefined) {
        if (completedObjects > totalObjects) {
            return { isValid: false, errorMsg: `completed_objects (${completedObjects}) cannot be greater than total_objects (${totalObjects})` };
        }
    }

    // Validate completed_at ISO8601 format
    if (completedAt !== null && completedAt !== undefined) {
        const iso8601Pattern = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$/;
        
        if (typeof completedAt !== 'string') {
            return { isValid: false, errorMsg: `completed_at must be a string in ISO8601 format, got: ${typeof completedAt}` };
        }
        
        if (!iso8601Pattern.test(completedAt)) {
            return { isValid: false, errorMsg: `completed_at must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '${completedAt}'` };
        }

        // Additional validation by attempting to parse
        try {
            new Date(completedAt).toISOString();
        } catch (e) {
            return { isValid: false, errorMsg: `completed_at is not a valid ISO8601 datetime: '${completedAt}'` };
        }
    }

    return { isValid: true, errorMsg: null };
}

function validateDevData(config, data) {
    // Intelligence is now an array of columns, table name is always 'access'
    if (!config.intelligence) {
        return { isValid: false, errorMsg: "No columns found in config.intelligence" };
    }

    const tableColumns = config.intelligence;
    if (!Array.isArray(tableColumns)) {
        return { isValid: false, errorMsg: "config.intelligence must be an array" };
    }

    if (tableColumns.length === 0) {
        return { isValid: false, errorMsg: "No columns found in config.intelligence" };
    }

    // Validate data is an array of objects
    if (!Array.isArray(data)) {
        return { isValid: false, errorMsg: "Data must be an array of objects" };
    }

    if (data.length === 0) {
        return { isValid: false, errorMsg: "Data array cannot be empty" };
    }

    // Validate first object matches expected columns and data types
    const firstObject = data[0];
    if (typeof firstObject !== 'object') {
        return { isValid: false, errorMsg: "Data array must contain objects" };
    }

    // The actual data will have scan_id, scan_execution_id, and scanned_at added by save_data
    const expectedTrackingFields = ['scan_id', 'scan_execution_id', 'scanned_at'];
    const expectedColumnNames = [...expectedTrackingFields, ...tableColumns.map(col => col.name)];

    const actualColumns = Object.keys(firstObject);

    // Check column names match and are in the same order
    if (actualColumns.length !== expectedColumnNames.length) {
        return { isValid: false, errorMsg: `Column names/order mismatch. Expected: ${expectedColumnNames}, Got: ${actualColumns}` };
    }

    for (let i = 0; i < expectedColumnNames.length; i++) {
        if (actualColumns[i] !== expectedColumnNames[i]) {
            return { isValid: false, errorMsg: `Column names/order mismatch. Expected: ${expectedColumnNames}, Got: ${actualColumns}` };
        }
    }

    // Validate tracking fields first
    const trackingFieldTypes = {
        'scan_id': 'LowCardinality(String)',
        'scan_execution_id': 'LowCardinality(String)', 
        'scanned_at': 'DateTime'
    };

    for (const [fieldName, fieldType] of Object.entries(trackingFieldTypes)) {
        const value = firstObject[fieldName];
        if (value === null || value === undefined) {
            return { isValid: false, errorMsg: `Required tracking field '${fieldName}' is missing` };
        }

        const result = validateClickHouseType(fieldName, fieldType, value);
        if (!result.isValid) {
            return result;
        }
    }

    // Validate data types for each column from intelligence config
    for (const columnDef of tableColumns) {
        const columnName = columnDef.name;
        const expectedType = columnDef.type;
        const nullable = columnDef.nullable !== false; // Default to true

        const value = firstObject[columnName];

        // Check nullable constraint
        if (!nullable && (value === null || value === undefined)) {
            return { isValid: false, errorMsg: `Column '${columnName}' cannot be null` };
        }

        // Skip type checking for null values if column is nullable
        if ((value === null || value === undefined) && nullable) {
            continue;
        }

        // ClickHouse type validation
        const result = validateClickHouseType(columnName, expectedType, value);
        if (!result.isValid) {
            return result;
        }
    }

    return { isValid: true, errorMsg: null };
}

function validateClickHouseType(columnName, expectedType, value) {
    // Handle Nullable types
    if (expectedType.startsWith('Nullable(') && expectedType.endsWith(')')) {
        if (value === null || value === undefined) {
            return { isValid: true, errorMsg: null };
        }
        // Extract inner type for non-null values
        const innerType = expectedType.slice(9, -1);
        return validateClickHouseType(columnName, innerType, value);
    }

    // Handle LowCardinality types
    if (expectedType.startsWith('LowCardinality(') && expectedType.endsWith(')')) {
        // Extract inner type
        const innerType = expectedType.slice(15, -1);
        return validateClickHouseType(columnName, innerType, value);
    }

    // Handle Array types
    if (expectedType.startsWith('Array(') && expectedType.endsWith(')')) {
        if (!Array.isArray(value)) {
            return { isValid: false, errorMsg: `Column '${columnName}' must be an array, got ${typeof value}` };
        }

        // Extract inner type and validate each element
        const innerType = expectedType.slice(6, -1);
        for (let i = 0; i < value.length; i++) {
            const result = validateClickHouseType(`${columnName}[${i}]`, innerType, value[i]);
            if (!result.isValid) {
                return result;
            }
        }
        return { isValid: true, errorMsg: null };
    }

    // Handle basic types
    switch (expectedType) {
        case 'String':
            if (typeof value !== 'string') {
                return { isValid: false, errorMsg: `Column '${columnName}' must be a string, got ${typeof value}` };
            }
            break;

        case 'DateTime':
            // Accept both date objects and ISO strings
            if (value instanceof Date) {
                return { isValid: true, errorMsg: null };
            } else if (typeof value === 'string') {
                // Validate ISO8601 format
                const isoPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$/;
                if (!isoPattern.test(value)) {
                    return { isValid: false, errorMsg: `Column '${columnName}' must be a valid ISO8601 datetime string, got '${value}'` };
                }

                // Try to parse to validate
                try {
                    new Date(value).toISOString();
                } catch (e) {
                    return { isValid: false, errorMsg: `Column '${columnName}' contains invalid datetime format: '${value}'` };
                }
            } else {
                return { isValid: false, errorMsg: `Column '${columnName}' must be a datetime object or ISO8601 string, got ${typeof value}` };
            }
            break;

        default:
            // For unknown types, just log a warning but don't fail validation
            console.log(`Warning: Unknown ClickHouse type '${expectedType}' for column '${columnName}', skipping type validation`);
            break;
    }

    return { isValid: true, errorMsg: null };
}

function validateResponse(functionType, responseData) {
    if (responseData.statusCode === 200) {
        // Success responses - validate based on function type
        switch (functionType) {
            case "test-connection":
                return validateTestConnectionResponse(responseData);
            case "access-scan":
                return validateAccessScanResponse(responseData);
            case "get-object":
                return validateGetObjectResponse(responseData);
            default:
                return { isValid: false, errorMsg: `Unknown function type: ${functionType}` };
        }
    } else {
        // Error responses - all function types use the same error format
        return validateErrorResponse(responseData);
    }
}

function validateTestConnectionResponse(responseData) {
    return validateTimestampResponse(responseData);
}

function validateAccessScanResponse(responseData) {
    return validateTimestampResponse(responseData);
}

function validateTimestampResponse(responseData) {
    if (!responseData.body || typeof responseData.body !== 'object') {
        return { isValid: false, errorMsg: "Response must contain a 'body' property" };
    }

    const body = responseData.body;
    const requiredKeys = ['startedAt', 'completedAt'];
    const bodyKeys = Object.keys(body);
    
    // Check for missing required keys
    const missingKeys = requiredKeys.filter(key => !bodyKeys.includes(key));
    if (missingKeys.length > 0) {
        return { isValid: false, errorMsg: `Response body missing required properties: ${missingKeys.sort()}` };
    }

    // Check for additional properties
    const extraKeys = bodyKeys.filter(key => !requiredKeys.includes(key));
    if (extraKeys.length > 0) {
        return { isValid: false, errorMsg: `Response body contains additional properties: ${extraKeys.sort()}` };
    }

    // Validate datetime formats (ISO8601)
    const iso8601Pattern = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$/;

    for (const fieldName of ['startedAt', 'completedAt']) {
        const fieldValue = body[fieldName];

        // Validate that field is a string
        if (typeof fieldValue !== 'string') {
            return { isValid: false, errorMsg: `Response body.${fieldName} must be a string, got ${typeof fieldValue}` };
        }

        // Validate ISO8601 format
        if (!iso8601Pattern.test(fieldValue)) {
            return { isValid: false, errorMsg: `Response body.${fieldName} must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '${fieldValue}'` };
        }

        // Additional validation by attempting to parse
        try {
            new Date(fieldValue).toISOString();
        } catch (e) {
            return { isValid: false, errorMsg: `Response body.${fieldName} is not a valid ISO8601 datetime: '${fieldValue}'` };
        }
    }

    // Validate that completedAt is after startedAt
    try {
        const startedAt = new Date(body.startedAt);
        const completedAt = new Date(body.completedAt);

        if (completedAt < startedAt) {
            return { isValid: false, errorMsg: `Response body.completedAt (${body.completedAt}) must be after startedAt (${body.startedAt})` };
        }
    } catch (e) {
        // If we can't parse for comparison, we've already validated format above
    }

    return { isValid: true, errorMsg: null };
}

function validateGetObjectResponse(responseData) {
    if (!responseData.body || typeof responseData.body !== 'object') {
        return { isValid: false, errorMsg: "Response must contain a 'body' property" };
    }

    const body = responseData.body;
    const bodyKeys = Object.keys(body);
    const expectedKeys = ['data'];

    // Check that body contains only 'data' property
    const extraKeys = bodyKeys.filter(key => !expectedKeys.includes(key));
    if (extraKeys.length > 0) {
        return { isValid: false, errorMsg: `Response body contains additional properties: ${extraKeys.sort()}` };
    }

    if (!body.hasOwnProperty('data')) {
        return { isValid: false, errorMsg: "Response body must contain a 'data' property" };
    }

    const dataValue = body.data;

    // Validate that data is a string
    if (typeof dataValue !== 'string') {
        return { isValid: false, errorMsg: `Response body.data must be a string, got ${typeof dataValue}` };
    }

    // Validate that data is not empty
    if (dataValue === '') {
        return { isValid: false, errorMsg: "Response body.data cannot be empty" };
    }

    // Check base64 format using regex
    const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Pattern.test(dataValue)) {
        return { isValid: false, errorMsg: "Response body.data is not valid base64 format" };
    }

    // Try to decode to verify it's valid base64
    try {
        Buffer.from(dataValue, 'base64');
    } catch (e) {
        return { isValid: false, errorMsg: "Response body.data is not valid base64 encoding" };
    }

    return { isValid: true, errorMsg: null };
}

function validateErrorResponse(responseData) {
    if (!responseData.body || typeof responseData.body !== 'object') {
        return { isValid: false, errorMsg: "Response must contain a 'body' property" };
    }

    const body = responseData.body;
    const bodyKeys = Object.keys(body);
    const requiredKeys = ['error'];

    // Check for missing required keys
    const missingKeys = requiredKeys.filter(key => !bodyKeys.includes(key));
    if (missingKeys.length > 0) {
        return { isValid: false, errorMsg: `Response body missing required properties: ${missingKeys.sort()}` };
    }

    // Check for additional properties
    const extraKeys = bodyKeys.filter(key => !requiredKeys.includes(key));
    if (extraKeys.length > 0) {
        return { isValid: false, errorMsg: `Response body contains additional properties: ${extraKeys.sort()}` };
    }

    // Validate error field
    const errorMessage = body.error;

    // Validate that error is a string
    if (typeof errorMessage !== 'string') {
        return { isValid: false, errorMsg: `Response body.error must be a string, got ${typeof errorMessage}` };
    }

    // Validate that error is not empty
    if (errorMessage.trim() === '') {
        return { isValid: false, errorMsg: "Response body.error cannot be empty" };
    }

    return { isValid: true, errorMsg: null };
}

module.exports = {
    validateRequestSchema,
    validateResponse,
    validateDevData,
    validateUpdateExecutionParams
};