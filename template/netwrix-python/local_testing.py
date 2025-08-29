import json

def validate_request_schema(config, request_data, function_type):
    """
    Validates request body against the expected schema based on the function type.
    
    Args:
        config (dict): Configuration dictionary containing variables schema
        request_data (dict): Request body to validate
        function_type (str): Function type from FUNCTION_TYPE environment variable
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(request_data, dict):
        return False, "Request body must be a JSON object"
    
    if not function_type:
        return False, "Missing FUNCTION_TYPE environment variable"
    
    valid_functions = ['test-connection', 'access-scan', 'get-object']
    if function_type not in valid_functions:
        return False, f"Invalid function type. Must be one of: {valid_functions}"
    
    # Define allowed top-level properties for each function type
    allowed_properties = {
        'test-connection': {'connection'},
        'access-scan': {'connection', 'accessScan'},
        'get-object': {'connection', 'location'}
    }
    
    # Check for additional properties at the top level
    actual_properties = set(request_data.keys())
    expected_properties = allowed_properties.get(function_type, set())
    extra_properties = actual_properties - expected_properties
    if extra_properties:
        return False, f"Additional properties not allowed for {function_type}: {sorted(list(extra_properties))}"
    
    # Validate connection object (required for all functions)
    if 'connection' not in request_data:
        return False, "Missing required field: 'connection'"
    
    connection_data = request_data['connection']
    if not isinstance(connection_data, dict):
        return False, "'connection' must be an object"
    
    # Validate connection fields against config.variables.connection
    connection_config = config.get('variables', {}).get('connection', [])
    is_valid, error_msg = _validate_object_against_schema(connection_data, connection_config, 'connection')
    if not is_valid:
        return False, error_msg
    
    # Function-specific validation
    if function_type == 'access-scan':
        if 'accessScan' not in request_data:
            return False, "Missing required field: 'accessScan' for access-scan function"
        
        access_scan_data = request_data['accessScan']
        if not isinstance(access_scan_data, dict):
            return False, "'accessScan' must be an object"
        
        # Validate accessScan fields against config.variables.accessScan
        access_scan_config = config.get('variables', {}).get('accessScan', [])
        is_valid, error_msg = _validate_object_against_schema(access_scan_data, access_scan_config, 'accessScan')
        if not is_valid:
            return False, error_msg
    
    elif function_type == 'get-object':
        if 'location' not in request_data:
            return False, "Missing required field: 'location' for get-object function"
        
        location_data = request_data['location']
        if not isinstance(location_data, dict):
            return False, "'location' must be an object"
        
        # Validate location fields against config.getObjectColumns
        get_object_columns = config.get('getObjectColumns', [])
        is_valid, error_msg = _validate_location_against_columns(location_data, get_object_columns)
        if not is_valid:
            return False, error_msg
    
    return True, None

def _validate_object_against_schema(data, schema_config, field_name):
    """
    Validates an object against a schema configuration.
    
    Args:
        data (dict): Data object to validate
        schema_config (list): List of field configurations
        field_name (str): Name of the field being validated (for error messages)
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Get list of allowed field keys from schema
    allowed_keys = {field_config.get('key') for field_config in schema_config if field_config.get('key')}
    
    # Check for additional properties not in schema
    actual_keys = set(data.keys())
    extra_keys = actual_keys - allowed_keys
    if extra_keys:
        return False, f"Additional properties not allowed in '{field_name}': {sorted(list(extra_keys))}"
    
    # Validate each field in schema
    for field_config in schema_config:
        field_key = field_config.get('key')
        field_type = field_config.get('type')
        required = field_config.get('required', False)
        
        value = data.get(field_key)
        
        # Check required fields
        if required and (value is None or value == ""):
            return False, f"Missing required field: '{field_name}.{field_key}'"
        
        # Skip validation for optional fields that are not provided
        if value is None and not required:
            continue
        
        # Type validation
        if field_type == 'text' or field_type == 'string':
            if not isinstance(value, str):
                return False, f"Field '{field_name}.{field_key}' must be a string, got {type(value).__name__}"
        elif field_type == 'number':
            if not isinstance(value, (int, float)):
                return False, f"Field '{field_name}.{field_key}' must be a number, got {type(value).__name__}"
            
            # Check min/max constraints
            min_val = field_config.get('min')
            max_val = field_config.get('max')
            if min_val is not None and value < min_val:
                return False, f"Field '{field_name}.{field_key}' must be >= {min_val}, got {value}"
            if max_val is not None and value > max_val:
                return False, f"Field '{field_name}.{field_key}' must be <= {max_val}, got {value}"
        elif field_type == 'checkbox':
            if not isinstance(value, bool):
                return False, f"Field '{field_name}.{field_key}' must be a boolean, got {type(value).__name__}"
        elif field_type == 'list':
            if value is not None:
                # For list fields, accept both arrays and single values
                if isinstance(value, str):
                    # Single string value - convert to list for validation
                    value_list = [value]
                elif isinstance(value, list):
                    value_list = value
                else:
                    return False, f"Field '{field_name}.{field_key}' must be a string or array, got {type(value).__name__}"
                
                # Validate options if specified
                options = field_config.get('options', [])
                if options:
                    valid_values = [opt.get('value') for opt in options if 'value' in opt]
                    for val in value_list:
                        if val not in valid_values:
                            return False, f"Field '{field_name}.{field_key}' contains invalid value '{val}'. Valid options: {valid_values}"
    
    return True, None

def _validate_location_against_columns(location_data, get_object_columns):
    """
    Validates location object against getObjectColumns configuration.
    
    Args:
        location_data (dict): Location data from request
        get_object_columns (list): List of objects with 'table' and 'column' properties
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Extract column names from the array of objects
    expected_columns = [col.get('column') for col in get_object_columns if col.get('column')]
    
    actual_columns = list(location_data.keys())
    
    # Check that all expected columns are present and in the correct order
    if len(actual_columns) != len(expected_columns):
        return False, f"Location must contain exactly {len(expected_columns)} columns. Expected: {expected_columns}, Got: {actual_columns}"
    
    # Check order and presence of columns
    for i, expected_col in enumerate(expected_columns):
        if i >= len(actual_columns) or actual_columns[i] != expected_col:
            return False, f"Location columns must match order and names. Expected: {expected_columns}, Got: {actual_columns}"
    
    # Validate that all values are strings (column values)
    for col_name, col_value in location_data.items():
        if not isinstance(col_value, str):
            return False, f"Location column '{col_name}' must be a string, got {type(col_value).__name__}"
    
    return True, None

def validate_update_execution_params(status, total_objects, completed_objects, increment_completed_objects, completed_at):
    """
    Validates parameters for update_execution method in dev environment.
    
    Returns:
        tuple: (is_valid, error_message)
    """
    # Validate status
    if status is not None:
        valid_statuses = ["running", "completed", "failed"]
        if status not in valid_statuses:
            return False, f"Invalid status: '{status}'. Must be one of: {valid_statuses}"
    
    # Validate total_objects
    if total_objects is not None:
        if not isinstance(total_objects, int) or total_objects < 0:
            return False, f"total_objects must be a non-negative integer, got: {total_objects}"
    
    # Validate completed_objects
    if completed_objects is not None:
        if not isinstance(completed_objects, int) or completed_objects < 0:
            return False, f"completed_objects must be a non-negative integer, got: {completed_objects}"
    
    # Validate increment_completed_objects
    if increment_completed_objects is not None:
        if not isinstance(increment_completed_objects, int) or increment_completed_objects < 0:
            return False, f"increment_completed_objects must be a non-negative integer, got: {increment_completed_objects}"
    
    # Check that only one of completed_objects or increment_completed_objects is provided
    if completed_objects is not None and increment_completed_objects is not None:
        return False, "Only one of completed_objects or increment_completed_objects can be provided, not both"
    
    # Check that completed_objects is not greater than total_objects
    if total_objects is not None and completed_objects is not None:
        if completed_objects > total_objects:
            return False, f"completed_objects ({completed_objects}) cannot be greater than total_objects ({total_objects})"
    
    # Validate completed_at ISO8601 format
    if completed_at is not None:
        import re
        from datetime import datetime
        
        # ISO8601 regex pattern - supports various formats
        iso8601_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$'
        
        if not isinstance(completed_at, str):
            return False, f"completed_at must be a string in ISO8601 format, got: {type(completed_at).__name__}"
        
        if not re.match(iso8601_pattern, completed_at):
            return False, f"completed_at must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '{completed_at}'"
        
        # Additional validation by attempting to parse
        try:
            # Try parsing common ISO8601 formats
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z']:
                try:
                    datetime.strptime(completed_at.replace('Z', '+00:00') if completed_at.endswith('Z') else completed_at, fmt.replace('%z', '+00:00') if fmt.endswith('%z') else fmt)
                    break
                except ValueError:
                    continue
            else:
                return False, f"completed_at is not a valid ISO8601 datetime: '{completed_at}'"
        except Exception:
            return False, f"completed_at is not a valid ISO8601 datetime: '{completed_at}'"
    
    return True, None

def validate_get_object_response(response_data):
    """
    Validates get-object response schema in dev environment.
    Expected schema: {"body": {"data": "<base64_string>"}}
    
    Returns:
        tuple: (is_valid, error_message)
    """
    import base64
    import re
    
    if not isinstance(response_data, dict):
        return False, "Response must be a dictionary"
    
    # Check for body property
    if 'body' not in response_data:
        return False, "Response must contain a 'body' property"
    
    body = response_data['body']
    if not isinstance(body, dict):
        return False, "Response body must be a dictionary"
    
    # Check that body contains only 'data' property
    body_keys = set(body.keys())
    expected_keys = {'data'}
    extra_keys = body_keys - expected_keys
    
    if extra_keys:
        return False, f"Response body contains additional properties: {sorted(list(extra_keys))}"
    
    if 'data' not in body:
        return False, "Response body must contain a 'data' property"
    
    data_value = body['data']
    
    # Validate that data is a string
    if not isinstance(data_value, str):
        return False, f"Response body.data must be a string, got {type(data_value).__name__}"
    
    # Validate that data is base64 encoded
    if not data_value:
        return False, "Response body.data cannot be empty"
    
    # Check base64 format using regex (basic check)
    base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
    if not re.match(base64_pattern, data_value):
        return False, "Response body.data is not valid base64 format"
    
    # Try to decode to verify it's valid base64
    try:
        base64.b64decode(data_value, validate=True)
    except Exception:
        return False, "Response body.data is not valid base64 encoding"
    
    return True, None

def validate_test_connection_response(response_data):
    """
    Validates test-connection response schema in dev environment.
    Expected schema: {"body": {"startedAt": "<datetime>", "completedAt": "<datetime>"}}
    
    Returns:
        tuple: (is_valid, error_message)
    """
    import re
    from datetime import datetime
    
    if not isinstance(response_data, dict):
        return False, "Response must be a dictionary"
    
    # Check for body property
    if 'body' not in response_data:
        return False, "Response must contain a 'body' property"
    
    body = response_data['body']
    if not isinstance(body, dict):
        return False, "Response body must be a dictionary"
    
    # Check that body contains only required properties
    body_keys = set(body.keys())
    required_keys = {'startedAt', 'completedAt'}
    
    # Check for missing required keys
    missing_keys = required_keys - body_keys
    if missing_keys:
        return False, f"Response body missing required properties: {sorted(list(missing_keys))}"
    
    # Check for additional properties
    extra_keys = body_keys - required_keys
    if extra_keys:
        return False, f"Response body contains additional properties: {sorted(list(extra_keys))}"
    
    # Validate datetime formats (ISO8601)
    iso8601_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$'
    
    for field_name in ['startedAt', 'completedAt']:
        field_value = body[field_name]
        
        # Validate that field is a string
        if not isinstance(field_value, str):
            return False, f"Response body.{field_name} must be a string, got {type(field_value).__name__}"
        
        # Validate ISO8601 format
        if not re.match(iso8601_pattern, field_value):
            return False, f"Response body.{field_name} must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '{field_value}'"
        
        # Additional validation by attempting to parse
        try:
            # Try parsing common ISO8601 formats
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z']:
                try:
                    datetime.strptime(field_value.replace('Z', '+00:00') if field_value.endswith('Z') else field_value, fmt.replace('%z', '+00:00') if fmt.endswith('%z') else fmt)
                    break
                except ValueError:
                    continue
            else:
                return False, f"Response body.{field_name} is not a valid ISO8601 datetime: '{field_value}'"
        except Exception:
            return False, f"Response body.{field_name} is not a valid ISO8601 datetime: '{field_value}'"
    
    # Validate that completedAt is after startedAt
    try:
        started_dt = datetime.fromisoformat(body['startedAt'].replace('Z', '+00:00'))
        completed_dt = datetime.fromisoformat(body['completedAt'].replace('Z', '+00:00'))
        
        if completed_dt < started_dt:
            return False, f"Response body.completedAt ({body['completedAt']}) must be after startedAt ({body['startedAt']})"
    except Exception:
        # If we can't parse for comparison, we've already validated format above
        pass
    
    return True, None

def validate_access_scan_response(response_data):
    """
    Validates access-scan response schema in dev environment.
    Expected schema: {"body": {"startedAt": "<datetime>", "completedAt": "<datetime>"}}
    
    Returns:
        tuple: (is_valid, error_message)
    """
    import re
    from datetime import datetime
    
    if not isinstance(response_data, dict):
        return False, "Response must be a dictionary"
    
    # Check for body property
    if 'body' not in response_data:
        return False, "Response must contain a 'body' property"
    
    body = response_data['body']
    if not isinstance(body, dict):
        return False, "Response body must be a dictionary"
    
    # Check that body contains only required properties
    body_keys = set(body.keys())
    required_keys = {'startedAt', 'completedAt'}
    
    # Check for missing required keys
    missing_keys = required_keys - body_keys
    if missing_keys:
        return False, f"Response body missing required properties: {sorted(list(missing_keys))}"
    
    # Check for additional properties
    extra_keys = body_keys - required_keys
    if extra_keys:
        return False, f"Response body contains additional properties: {sorted(list(extra_keys))}"
    
    # Validate datetime formats (ISO8601)
    iso8601_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$'
    
    for field_name in ['startedAt', 'completedAt']:
        field_value = body[field_name]
        
        # Validate that field is a string
        if not isinstance(field_value, str):
            return False, f"Response body.{field_name} must be a string, got {type(field_value).__name__}"
        
        # Validate ISO8601 format
        if not re.match(iso8601_pattern, field_value):
            return False, f"Response body.{field_name} must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '{field_value}'"
        
        # Additional validation by attempting to parse
        try:
            # Try parsing common ISO8601 formats
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z']:
                try:
                    datetime.strptime(field_value.replace('Z', '+00:00') if field_value.endswith('Z') else field_value, fmt.replace('%z', '+00:00') if fmt.endswith('%z') else fmt)
                    break
                except ValueError:
                    continue
            else:
                return False, f"Response body.{field_name} is not a valid ISO8601 datetime: '{field_value}'"
        except Exception:
            return False, f"Response body.{field_name} is not a valid ISO8601 datetime: '{field_value}'"
    
    # Validate that completedAt is after startedAt
    try:
        started_dt = datetime.fromisoformat(body['startedAt'].replace('Z', '+00:00'))
        completed_dt = datetime.fromisoformat(body['completedAt'].replace('Z', '+00:00'))
        
        if completed_dt < started_dt:
            return False, f"Response body.completedAt ({body['completedAt']}) must be after startedAt ({body['startedAt']})"
    except Exception:
        # If we can't parse for comparison, we've already validated format above
        pass
    
    return True, None

def validate_error_response(response_data):
    """
    Validates error response schema in dev environment.
    Expected schema: {"body": {"error": "<string>"}}
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(response_data, dict):
        return False, "Response must be a dictionary"
    
    # Check for body property
    if 'body' not in response_data:
        return False, "Response must contain a 'body' property"
    
    body = response_data['body']
    if not isinstance(body, dict):
        return False, "Response body must be a dictionary"
    
    # Check that body contains only the required property
    body_keys = set(body.keys())
    required_keys = {'error'}
    
    # Check for missing required keys
    missing_keys = required_keys - body_keys
    if missing_keys:
        return False, f"Response body missing required properties: {sorted(list(missing_keys))}"
    
    # Check for additional properties
    extra_keys = body_keys - required_keys
    if extra_keys:
        return False, f"Response body contains additional properties: {sorted(list(extra_keys))}"
    
    # Validate error field
    error_message = body['error']
    
    # Validate that error is a string
    if not isinstance(error_message, str):
        return False, f"Response body.error must be a string, got {type(error_message).__name__}"
    
    # Validate that error is not empty
    if not error_message.strip():
        return False, "Response body.error cannot be empty"
    
    return True, None

def validate_dev_data(config, table, data):
    """
    Validates data for DEV environment against config schema.
    
    Args:
        config (dict): Configuration dictionary
        table (str): Name of the table for validation
        data (list): Array of data objects to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    
    # Look for the specific table in intelligence configuration
    intelligence = config.get('intelligence', [])
    if not isinstance(intelligence, list):
        return False, "config.intelligence must be an array"
    
    # Find the table object in the intelligence array
    table_config = None
    for table_obj in intelligence:
        if isinstance(table_obj, dict) and table_obj.get('name') == table:
            table_config = table_obj
            break
    
    if not table_config:
        return False, f"Table '{table}' not found in config.intelligence"
    
    table_columns = table_config.get('columns', [])
    if not table_columns:
        return False, f"No columns found for table '{table}' in config.intelligence"
    
    # Validate data is an array of objects
    if not isinstance(data, list):
        return False, "Data must be an array of objects"
    
    if len(data) == 0:
        return False, "Data array cannot be empty"
    
    # Validate first object matches expected columns and data types
    first_object = data[0]
    if not isinstance(first_object, dict):
        return False, "Data array must contain objects"
    
    # The actual data will have scan_id, scan_execution_id, and scanned_at added by save_data
    expected_tracking_fields = ['scan_id', 'scan_execution_id', 'scanned_at']
    expected_column_names = expected_tracking_fields + [col.get('name') for col in table_columns]
    
    actual_columns = list(first_object.keys())
    
    # Check column names match and are in the same order
    if actual_columns != expected_column_names:
        return False, f"Column names/order mismatch. Expected: {expected_column_names}, Got: {actual_columns}"
    
    # Validate tracking fields first
    tracking_field_types = {
        'scan_id': 'LowCardinality(String)',
        'scan_execution_id': 'LowCardinality(String)', 
        'scanned_at': 'DateTime'
    }
    
    for field_name, field_type in tracking_field_types.items():
        value = first_object.get(field_name)
        if value is None:
            return False, f"Required tracking field '{field_name}' is missing"
        
        is_valid, type_error = _validate_clickhouse_type(field_name, field_type, value)
        if not is_valid:
            return False, type_error
    
    # Validate data types for each column from intelligence config
    for column_def in table_columns:
        column_name = column_def.get('name')
        expected_type = column_def.get('type')
        nullable = column_def.get('nullable', True)
        value = first_object.get(column_name)
        
        # Check nullable constraint
        if not nullable and value is None:
            return False, f"Column '{column_name}' cannot be null"
        
        # Skip type checking for null values if column is nullable
        if value is None and nullable:
            continue
        
        # ClickHouse type validation
        is_valid, type_error = _validate_clickhouse_type(column_name, expected_type, value)
        if not is_valid:
            return False, type_error
    
    return True, None

def _validate_clickhouse_type(column_name, expected_type, value):
    """
    Validates a value against a ClickHouse data type.
    
    Args:
        column_name (str): Name of the column for error messages
        expected_type (str): ClickHouse data type string
        value: The value to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    import re
    from datetime import datetime
    
    # Handle Nullable types
    if expected_type.startswith('Nullable(') and expected_type.endswith(')'):
        if value is None:
            return True, None
        # Extract inner type for non-null values
        inner_type = expected_type[9:-1]  # Remove 'Nullable(' and ')'
        return _validate_clickhouse_type(column_name, inner_type, value)
    
    # Handle LowCardinality types
    if expected_type.startswith('LowCardinality(') and expected_type.endswith(')'):
        # Extract inner type
        inner_type = expected_type[15:-1]  # Remove 'LowCardinality(' and ')'
        return _validate_clickhouse_type(column_name, inner_type, value)
    
    # Handle Array types
    if expected_type.startswith('Array(') and expected_type.endswith(')'):
        if not isinstance(value, list):
            return False, f"Column '{column_name}' must be an array, got {type(value).__name__}"
        
        # Extract inner type and validate each element
        inner_type = expected_type[6:-1]  # Remove 'Array(' and ')'
        for i, item in enumerate(value):
            is_valid, error = _validate_clickhouse_type(f"{column_name}[{i}]", inner_type, item)
            if not is_valid:
                return False, error
        return True, None
    
    # Handle Enum8 types
    if expected_type.startswith('Enum8(') and expected_type.endswith(')'):
        if not isinstance(value, str):
            return False, f"Column '{column_name}' must be a string (enum value), got {type(value).__name__}"
        
        # Extract enum values from the type definition
        enum_part = expected_type[6:-1]  # Remove 'Enum8(' and ')'
        # Parse enum values like 'SUCCESS' = 1, 'ERROR' = 2
        enum_values = []
        for match in re.finditer(r"'([^']+)'\s*=\s*\d+", enum_part):
            enum_values.append(match.group(1))
        
        if enum_values and value not in enum_values:
            return False, f"Column '{column_name}' must be one of {enum_values}, got '{value}'"
        return True, None
    
    # Handle Nested types
    if expected_type.startswith('Nested(') and expected_type.endswith(')'):
        if not isinstance(value, dict):
            return False, f"Column '{column_name}' must be a nested object (dict), got {type(value).__name__}"
        
        # Parse nested structure
        nested_def = expected_type[7:-1]  # Remove 'Nested(' and ')'
        # This is a simplified parser - in reality, nested types are more complex
        # For now, just validate it's a dict with the expected structure
        return True, None
    
    # Handle basic types
    if expected_type == 'String':
        if not isinstance(value, str):
            return False, f"Column '{column_name}' must be a string, got {type(value).__name__}"
    
    elif expected_type in ['Int8', 'Int16', 'Int32', 'Int64', 'UInt8', 'UInt16', 'UInt32', 'UInt64']:
        if not isinstance(value, int):
            return False, f"Column '{column_name}' must be an integer, got {type(value).__name__}"
        
        # Validate integer ranges
        ranges = {
            'Int8': (-128, 127),
            'Int16': (-32768, 32767), 
            'Int32': (-2147483648, 2147483647),
            'Int64': (-9223372036854775808, 9223372036854775807),
            'UInt8': (0, 255),
            'UInt16': (0, 65535),
            'UInt32': (0, 4294967295),
            'UInt64': (0, 18446744073709551615)
        }
        
        if expected_type in ranges:
            min_val, max_val = ranges[expected_type]
            if value < min_val or value > max_val:
                return False, f"Column '{column_name}' value {value} is out of range for {expected_type} ({min_val} to {max_val})"
    
    elif expected_type in ['Float32', 'Float64']:
        if not isinstance(value, (int, float)):
            return False, f"Column '{column_name}' must be a number, got {type(value).__name__}"
    
    elif expected_type == 'Bool':
        if not isinstance(value, bool):
            return False, f"Column '{column_name}' must be a boolean, got {type(value).__name__}"
    
    elif expected_type == 'DateTime':
        # Accept both datetime objects and ISO strings
        if isinstance(value, datetime):
            return True, None
        elif isinstance(value, str):
            # Validate ISO8601 format
            iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$'
            if not re.match(iso_pattern, value):
                return False, f"Column '{column_name}' must be a valid ISO8601 datetime string, got '{value}'"
            
            # Try to parse to validate
            try:
                # Handle various formats
                if value.endswith('Z'):
                    value = value.replace('Z', '+00:00')
                datetime.fromisoformat(value)
            except ValueError:
                return False, f"Column '{column_name}' contains invalid datetime format: '{value}'"
        else:
            return False, f"Column '{column_name}' must be a datetime object or ISO8601 string, got {type(value).__name__}"
    
    elif expected_type in ['Date', 'Date32']:
        if isinstance(value, str):
            # Validate date format YYYY-MM-DD
            date_pattern = r'^\d{4}-\d{2}-\d{2}$'
            if not re.match(date_pattern, value):
                return False, f"Column '{column_name}' must be a valid date string (YYYY-MM-DD), got '{value}'"
            
            try:
                datetime.strptime(value, '%Y-%m-%d')
            except ValueError:
                return False, f"Column '{column_name}' contains invalid date: '{value}'"
        else:
            return False, f"Column '{column_name}' must be a date string (YYYY-MM-DD), got {type(value).__name__}"
    
    else:
        # For unknown types, just log a warning but don't fail validation
        print(f"Warning: Unknown ClickHouse type '{expected_type}' for column '{column_name}', skipping type validation", flush=True)
    
    return True, None

def validate_response(function_type, response_data):
    """
    Validates response data based on function type by selecting the appropriate validation function.
    
    Args:
        function_type (str): The type of function ('test-connection', 'access-scan', 'get-object')
        response_data (dict): The response data to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if response_data.get('statusCode') == 200:
        # Success responses - validate based on function type
        if function_type == "test-connection":
            return validate_test_connection_response(response_data)
        elif function_type == "access-scan":
            return validate_access_scan_response(response_data)
        elif function_type == "get-object":
            return validate_get_object_response(response_data)
        else:
            return False, f"Unknown function type: {function_type}"
    else:
        # Error responses - all function types use the same error format
        return validate_error_response(response_data)