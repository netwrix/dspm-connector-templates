import json

def validate_dev_data(config, table, data):
    """
    Validates data for DEV environment against config schema.
    
    Args:
        config (str): JSON configuration string
        table (str): Table name to validate against
        data (list): Array of data objects to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if config is None:
        return False, "Config is required in DEV environment"
    
    try:
        # Parse config JSON
        config = json.loads(config)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in config: {str(e)}"
    
    # Check if table exists in config.intelligence array
    tables = config.get('intelligence', [])
    table_config = None
    for table_def in tables:
        if table_def.get('name') == table:
            table_config = table_def
            break
    
    if table_config is None:
        return False, f"Table '{table}' not found in config.intelligence"
    
    # Validate data is an array of objects
    if not isinstance(data, list):
        return False, "Data must be an array of objects"
    
    if len(data) == 0:
        return False, "Data array cannot be empty"
    
    # Validate first object matches expected columns and data types
    first_object = data[0]
    if not isinstance(first_object, dict):
        return False, "Data array must contain objects"
    
    expected_columns = table_config.get('columns', [])
    actual_columns = list(first_object.keys())
    expected_column_names = [col.get('name') for col in expected_columns]
    
    # Check column names match and are in the same order
    if actual_columns != expected_column_names:
        return False, f"Column names/order mismatch. Expected: {expected_column_names}, Got: {actual_columns}"
    
    # Validate data types for each column
    for column_def in expected_columns:
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
        
        # Type validation
        if expected_type == "String":
            if not isinstance(value, str):
                return False, f"Column '{column_name}' must be a string, got {type(value).__name__}"
        elif expected_type == "Integer":
            if not isinstance(value, int):
                return False, f"Column '{column_name}' must be an integer, got {type(value).__name__}"
        elif expected_type == "Boolean":
            if not isinstance(value, bool):
                return False, f"Column '{column_name}' must be a boolean, got {type(value).__name__}"
        elif expected_type == "DateTime":
            if not isinstance(value, str):
                return False, f"Column '{column_name}' must be a datetime string, got {type(value).__name__}"
        elif expected_type == "Array":
            if not isinstance(value, list):
                return False, f"Column '{column_name}' must be an array, got {type(value).__name__}"
            
            # Check array item types if specified
            items_type = column_def.get('items')
            if items_type == "String":
                for item in value:
                    if not isinstance(item, str):
                        return False, f"Column '{column_name}' array must contain strings, got {type(item).__name__}"
    
    return True, None