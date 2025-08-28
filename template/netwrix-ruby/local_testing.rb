require 'json'
require 'base64'
require 'time'

module LocalTesting
  def self.validate_request_schema(config, request_data, function_type)
    return [false, "Request body must be a JSON object"] unless request_data.is_a?(Hash)
    return [false, "Missing FUNCTION_TYPE environment variable"] if function_type.nil? || function_type.empty?

    valid_functions = ['test-connection', 'access-scan', 'get-object']
    return [false, "Invalid function type. Must be one of: #{valid_functions}"] unless valid_functions.include?(function_type)

    # Define allowed top-level properties for each function type
    allowed_properties = {
      'test-connection' => ['connection'],
      'access-scan' => ['connection', 'accessScan'],
      'get-object' => ['connection', 'location']
    }

    # Check for additional properties at the top level
    actual_properties = request_data.keys
    expected_properties = allowed_properties[function_type]
    extra_properties = actual_properties - expected_properties
    return [false, "Additional properties not allowed for #{function_type}: #{extra_properties.sort}"] unless extra_properties.empty?

    # Validate connection object (required for all functions)
    return [false, "Missing required field: 'connection'"] unless request_data.key?('connection')
    return [false, "'connection' must be an object"] unless request_data['connection'].is_a?(Hash)

    # Validate connection fields against config.variables.connection
    if config['variables'] && config['variables']['connection']
      is_valid, error_msg = validate_object_against_schema(request_data['connection'], config['variables']['connection'], 'connection')
      return [false, error_msg] unless is_valid
    end

    # Function-specific validation
    if function_type == 'access-scan'
      return [false, "Missing required field: 'accessScan' for access-scan function"] unless request_data.key?('accessScan')
      return [false, "'accessScan' must be an object"] unless request_data['accessScan'].is_a?(Hash)

      # Validate accessScan fields against config.variables.accessScan
      if config['variables'] && config['variables']['accessScan']
        is_valid, error_msg = validate_object_against_schema(request_data['accessScan'], config['variables']['accessScan'], 'accessScan')
        return [false, error_msg] unless is_valid
      end
    elsif function_type == 'get-object'
      return [false, "Missing required field: 'location' for get-object function"] unless request_data.key?('location')
      return [false, "'location' must be an object"] unless request_data['location'].is_a?(Hash)

      # Validate location fields against config.getObjectColumns
      if config['getObjectColumns']
        is_valid, error_msg = validate_location_against_columns(request_data['location'], config['getObjectColumns'])
        return [false, error_msg] unless is_valid
      end
    end

    [true, nil]
  end

  def self.validate_object_against_schema(data, schema_config, field_name)
    # Get list of allowed field keys from schema
    allowed_keys = schema_config.map { |field_config| field_config['key'] }.compact.to_set

    # Check for additional properties not in schema
    actual_keys = data.keys.to_set
    extra_keys = actual_keys - allowed_keys
    return [false, "Additional properties not allowed in '#{field_name}': #{extra_keys.sort}"] unless extra_keys.empty?

    # Validate each field in schema
    schema_config.each do |field_config|
      next unless field_config['key']

      field_key = field_config['key']
      field_type = field_config['type']
      required = field_config['required'] || false

      value = data[field_key]

      # Check required fields
      if required && (value.nil? || value == "")
        return [false, "Missing required field: '#{field_name}.#{field_key}'"]
      end

      # Skip validation for optional fields that are not provided
      next if value.nil? && !required

      # Type validation
      case field_type
      when 'text', 'string'
        return [false, "Field '#{field_name}.#{field_key}' must be a string, got #{value.class}"] unless value.is_a?(String)
      when 'number'
        return [false, "Field '#{field_name}.#{field_key}' must be a number, got #{value.class}"] unless value.is_a?(Numeric)

        # Check min/max constraints
        if field_config['min'] && value < field_config['min']
          return [false, "Field '#{field_name}.#{field_key}' must be >= #{field_config['min']}, got #{value}"]
        end
        if field_config['max'] && value > field_config['max']
          return [false, "Field '#{field_name}.#{field_key}' must be <= #{field_config['max']}, got #{value}"]
        end
      when 'checkbox'
        return [false, "Field '#{field_name}.#{field_key}' must be a boolean, got #{value.class}"] unless [TrueClass, FalseClass].include?(value.class)
      when 'list'
        unless value.nil?
          # For list fields, accept both arrays and single values
          value_list = value.is_a?(String) ? [value] : (value.is_a?(Array) ? value : nil)
          return [false, "Field '#{field_name}.#{field_key}' must be a string or array, got #{value.class}"] if value_list.nil?

          # Validate options if specified
          if field_config['options'] && !field_config['options'].empty?
            valid_values = field_config['options'].map { |opt| opt['value'] }.compact
            unless valid_values.empty?
              value_list.each do |val|
                unless valid_values.include?(val)
                  return [false, "Field '#{field_name}.#{field_key}' contains invalid value '#{val}'. Valid options: #{valid_values}"]
                end
              end
            end
          end
        end
      end
    end

    [true, nil]
  end

  def self.validate_location_against_columns(location_data, get_object_columns)
    expected_columns = get_object_columns
    actual_columns = location_data.keys

    # Check that all expected columns are present and in the correct order
    return [false, "Location must contain exactly #{expected_columns.length} columns. Expected: #{expected_columns}, Got: #{actual_columns}"] if actual_columns.length != expected_columns.length

    # Check order and presence of columns
    expected_columns.each_with_index do |expected_col, i|
      return [false, "Location columns must match order and names. Expected: #{expected_columns}, Got: #{actual_columns}"] if i >= actual_columns.length || actual_columns[i] != expected_col
    end

    # Validate that all values are strings (column values)
    location_data.each do |col_name, col_value|
      return [false, "Location column '#{col_name}' must be a string, got #{col_value.class}"] unless col_value.is_a?(String)
    end

    [true, nil]
  end

  def self.validate_update_execution_params(status, total_objects, completed_objects, increment_completed_objects, completed_at)
    # Validate status
    if !status.nil?
      valid_statuses = ["running", "completed", "failed"]
      return [false, "Invalid status: '#{status}'. Must be one of: #{valid_statuses}"] unless valid_statuses.include?(status)
    end

    # Validate total_objects
    if !total_objects.nil?
      return [false, "total_objects must be a non-negative integer, got: #{total_objects}"] unless total_objects.is_a?(Integer) && total_objects >= 0
    end

    # Validate completed_objects
    if !completed_objects.nil?
      return [false, "completed_objects must be a non-negative integer, got: #{completed_objects}"] unless completed_objects.is_a?(Integer) && completed_objects >= 0
    end

    # Validate increment_completed_objects
    if !increment_completed_objects.nil?
      return [false, "increment_completed_objects must be a non-negative integer, got: #{increment_completed_objects}"] unless increment_completed_objects.is_a?(Integer) && increment_completed_objects >= 0
    end

    # Check that only one of completed_objects or increment_completed_objects is provided
    if !completed_objects.nil? && !increment_completed_objects.nil?
      return [false, "Only one of completed_objects or increment_completed_objects can be provided, not both"]
    end

    # Check that completed_objects is not greater than total_objects
    if !total_objects.nil? && !completed_objects.nil? && completed_objects > total_objects
      return [false, "completed_objects (#{completed_objects}) cannot be greater than total_objects (#{total_objects})"]
    end

    # Validate completed_at ISO8601 format
    if !completed_at.nil?
      iso8601_pattern = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$/
      
      return [false, "completed_at must be a string in ISO8601 format, got: #{completed_at.class}"] unless completed_at.is_a?(String)
      return [false, "completed_at must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '#{completed_at}'"] unless iso8601_pattern.match?(completed_at)

      # Additional validation by attempting to parse
      begin
        Time.parse(completed_at)
      rescue
        return [false, "completed_at is not a valid ISO8601 datetime: '#{completed_at}'"]
      end
    end

    [true, nil]
  end

  def self.validate_dev_data(config, data)
    # Intelligence is now an array of columns, table name is always 'access'
    return [false, "No columns found in config.intelligence"] unless config['intelligence']

    table_columns = config['intelligence']
    return [false, "config.intelligence must be an array"] unless table_columns.is_a?(Array)
    return [false, "No columns found in config.intelligence"] if table_columns.empty?

    # Validate data is an array of objects
    return [false, "Data must be an array of objects"] unless data.is_a?(Array)
    return [false, "Data array cannot be empty"] if data.empty?

    # Validate first object matches expected columns and data types
    first_object = data[0]
    return [false, "Data array must contain objects"] unless first_object.is_a?(Hash)

    # The actual data will have scan_id, scan_execution_id, and scanned_at added by save_data
    expected_tracking_fields = ['scan_id', 'scan_execution_id', 'scanned_at']
    expected_column_names = expected_tracking_fields + table_columns.map { |col| col['name'] }.compact

    actual_columns = first_object.keys

    # Check column names match and are in the same order
    return [false, "Column names/order mismatch. Expected: #{expected_column_names}, Got: #{actual_columns}"] if actual_columns.length != expected_column_names.length

    expected_column_names.each_with_index do |expected, i|
      return [false, "Column names/order mismatch. Expected: #{expected_column_names}, Got: #{actual_columns}"] if actual_columns[i] != expected
    end

    # Validate tracking fields first
    tracking_field_types = {
      'scan_id' => 'LowCardinality(String)',
      'scan_execution_id' => 'LowCardinality(String)', 
      'scanned_at' => 'DateTime'
    }

    tracking_field_types.each do |field_name, field_type|
      value = first_object[field_name]
      return [false, "Required tracking field '#{field_name}' is missing"] if value.nil?

      is_valid, type_error = validate_clickhouse_type(field_name, field_type, value)
      return [false, type_error] unless is_valid
    end

    # Validate data types for each column from intelligence config
    table_columns.each do |column_def|
      next unless column_def['name'] && column_def['type']

      column_name = column_def['name']
      expected_type = column_def['type']
      nullable = column_def['nullable'] != false # Default to true

      value = first_object[column_name]

      # Check nullable constraint
      return [false, "Column '#{column_name}' cannot be null"] if !nullable && value.nil?

      # Skip type checking for null values if column is nullable
      next if value.nil? && nullable

      # ClickHouse type validation
      is_valid, type_error = validate_clickhouse_type(column_name, expected_type, value)
      return [false, type_error] unless is_valid
    end

    [true, nil]
  end

  def self.validate_clickhouse_type(column_name, expected_type, value)
    # Handle Nullable types
    if expected_type.start_with?('Nullable(') && expected_type.end_with?(')')
      return [true, nil] if value.nil?
      # Extract inner type for non-null values
      inner_type = expected_type[9...-1]
      return validate_clickhouse_type(column_name, inner_type, value)
    end

    # Handle LowCardinality types
    if expected_type.start_with?('LowCardinality(') && expected_type.end_with?(')')
      # Extract inner type
      inner_type = expected_type[15...-1]
      return validate_clickhouse_type(column_name, inner_type, value)
    end

    # Handle Array types
    if expected_type.start_with?('Array(') && expected_type.end_with?(')')
      return [false, "Column '#{column_name}' must be an array, got #{value.class}"] unless value.is_a?(Array)

      # Extract inner type and validate each element
      inner_type = expected_type[6...-1]
      value.each_with_index do |item, i|
        is_valid, error = validate_clickhouse_type("#{column_name}[#{i}]", inner_type, item)
        return [false, error] unless is_valid
      end
      return [true, nil]
    end

    # Handle basic types
    case expected_type
    when 'String'
      return [false, "Column '#{column_name}' must be a string, got #{value.class}"] unless value.is_a?(String)
    when 'DateTime'
      # Accept both time objects and ISO strings
      if value.is_a?(Time)
        return [true, nil]
      elsif value.is_a?(String)
        # Validate ISO8601 format
        iso_pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$/
        return [false, "Column '#{column_name}' must be a valid ISO8601 datetime string, got '#{value}'"] unless iso_pattern.match?(value)

        # Try to parse to validate
        begin
          Time.parse(value)
        rescue
          return [false, "Column '#{column_name}' contains invalid datetime format: '#{value}'"]
        end
      else
        return [false, "Column '#{column_name}' must be a datetime object or ISO8601 string, got #{value.class}"]
      end
    else
      # For unknown types, just log a warning but don't fail validation
      puts "Warning: Unknown ClickHouse type '#{expected_type}' for column '#{column_name}', skipping type validation"
    end

    [true, nil]
  end

  def self.validate_response(function_type, response_data)
    if response_data[:statusCode] == 200
      # Success responses - validate based on function type
      case function_type
      when "test-connection"
        validate_test_connection_response(response_data)
      when "access-scan"
        validate_access_scan_response(response_data)
      when "get-object"
        validate_get_object_response(response_data)
      else
        [false, "Unknown function type: #{function_type}"]
      end
    else
      # Error responses - all function types use the same error format
      validate_error_response(response_data)
    end
  end

  def self.validate_test_connection_response(response_data)
    validate_timestamp_response(response_data)
  end

  def self.validate_access_scan_response(response_data)
    validate_timestamp_response(response_data)
  end

  def self.validate_timestamp_response(response_data)
    return [false, "Response must contain a 'body' property"] unless response_data[:body] && response_data[:body].is_a?(Hash)

    body = response_data[:body]
    required_keys = ['startedAt', 'completedAt']
    body_keys = body.keys.map(&:to_s)
    
    # Check for missing required keys
    missing_keys = required_keys - body_keys
    return [false, "Response body missing required properties: #{missing_keys.sort}"] unless missing_keys.empty?

    # Check for additional properties
    extra_keys = body_keys - required_keys
    return [false, "Response body contains additional properties: #{extra_keys.sort}"] unless extra_keys.empty?

    # Validate datetime formats (ISO8601)
    iso8601_pattern = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))$/

    ['startedAt', 'completedAt'].each do |field_name|
      field_value = body[field_name.to_sym] || body[field_name]

      # Validate that field is a string
      return [false, "Response body.#{field_name} must be a string, got #{field_value.class}"] unless field_value.is_a?(String)

      # Validate ISO8601 format
      return [false, "Response body.#{field_name} must be in ISO8601 format (e.g., '2023-12-25T10:30:00Z'), got: '#{field_value}'"] unless iso8601_pattern.match?(field_value)

      # Additional validation by attempting to parse
      begin
        Time.parse(field_value)
      rescue
        return [false, "Response body.#{field_name} is not a valid ISO8601 datetime: '#{field_value}'"]
      end
    end

    # Validate that completedAt is after startedAt
    begin
      started_at = Time.parse(body[:startedAt] || body['startedAt'])
      completed_at = Time.parse(body[:completedAt] || body['completedAt'])

      if completed_at < started_at
        return [false, "Response body.completedAt (#{body[:completedAt] || body['completedAt']}) must be after startedAt (#{body[:startedAt] || body['startedAt']})"]
      end
    rescue
      # If we can't parse for comparison, we've already validated format above
    end

    [true, nil]
  end

  def self.validate_get_object_response(response_data)
    return [false, "Response must contain a 'body' property"] unless response_data[:body] && response_data[:body].is_a?(Hash)

    body = response_data[:body]
    expected_keys = ['data']

    # Check that body contains only 'data' property
    body_keys = body.keys.map(&:to_s)
    extra_keys = body_keys - expected_keys
    return [false, "Response body contains additional properties: #{extra_keys.sort}"] unless extra_keys.empty?

    return [false, "Response body must contain a 'data' property"] unless body.key?(:data) || body.key?('data')

    data_value = body[:data] || body['data']

    # Validate that data is a string
    return [false, "Response body.data must be a string, got #{data_value.class}"] unless data_value.is_a?(String)

    # Validate that data is not empty
    return [false, "Response body.data cannot be empty"] if data_value.empty?

    # Check base64 format using regex
    base64_pattern = /^[A-Za-z0-9+\/]*={0,2}$/
    return [false, "Response body.data is not valid base64 format"] unless base64_pattern.match?(data_value)

    # Try to decode to verify it's valid base64
    begin
      Base64.decode64(data_value)
    rescue
      return [false, "Response body.data is not valid base64 encoding"]
    end

    [true, nil]
  end

  def self.validate_error_response(response_data)
    return [false, "Response must contain a 'body' property"] unless response_data[:body] && response_data[:body].is_a?(Hash)

    body = response_data[:body]
    required_keys = ['error']

    # Check for missing required keys
    body_keys = body.keys.map(&:to_s)
    missing_keys = required_keys - body_keys
    return [false, "Response body missing required properties: #{missing_keys.sort}"] unless missing_keys.empty?

    # Check for additional properties
    extra_keys = body_keys - required_keys
    return [false, "Response body contains additional properties: #{extra_keys.sort}"] unless extra_keys.empty?

    # Validate error field
    error_message = body[:error] || body['error']

    # Validate that error is a string
    return [false, "Response body.error must be a string, got #{error_message.class}"] unless error_message.is_a?(String)

    # Validate that error is not empty
    return [false, "Response body.error cannot be empty"] if error_message.strip.empty?

    [true, nil]
  end
end