require_relative 'function/handler'
require_relative 'local_testing'

require 'sinatra'
require 'json'
require 'net/http'
require 'uri'
require 'base64'
require 'time'

set :port, 5000
# set :bind, '0.0.0.0'

class Context
  attr_accessor :hostname, :secrets, :scan_id, :sync_id, :scan_execution_id, 
                :sync_execution_id, :run_local, :config, :function_type

  def initialize
    @hostname = ENV['HOSTNAME'] || 'localhost'
    @secrets = {}
    @scan_id = ENV['SCAN_ID']
    @sync_id = ENV['SYNC_ID']
    @scan_execution_id = nil
    @sync_execution_id = nil
    @run_local = ENV['RUN_LOCAL'] || 'false'
    @config = ENV['CONFIG'] ? JSON.parse(ENV['CONFIG']) : nil
    @function_type = ENV['FUNCTION_TYPE']
  end

  def test_connection_success_response
    {
      statusCode: 200,
      body: {}
    }
  end

  def access_scan_success_response
    {
      statusCode: 200,
      body: {}
    }
  end

  def get_object_success_response(data)
    encoded_data = Base64.encode64(data).strip
    
    {
      statusCode: 200,
      body: { data: encoded_data }
    }
  end

  def error_response(client_error, error_msg)
    status_code = client_error ? 400 : 500

    {
      statusCode: status_code,
      body: { error: error_msg }
    }
  end

  def save_data(data)
    # Add scan_id, scan_execution_id, and scanned_at to each row
    enhanced_data = []
    current_time = Time.now.utc.iso8601

    local_run = @run_local == "true"
    scan_id = local_run ? "scan0001" : @scan_id
    scan_execution_id = local_run ? "scan-0002" : @scan_execution_id
    
    data.each do |row|
      enhanced_row = {
        'scan_id' => scan_id,
        'scan_execution_id' => scan_execution_id,
        'scanned_at' => current_time
      }.merge(row)
      enhanced_data << enhanced_row
    end
    
    # Dev environment validation
    if local_run
      is_valid, error_msg = LocalTesting.validate_dev_data(@config, enhanced_data)
      if !is_valid
        puts error_msg
        return { success: false, error: error_msg }
      else
        puts "Saving #{enhanced_data.length} items to table"
        puts "Sample item: #{JSON.pretty_generate(enhanced_data[0])}" if enhanced_data.length > 0
        return { success: true, error: nil }
      end
    else
      save_data_function = ENV['SAVE_DATA_FUNCTION']
      if !save_data_function
        error_msg = "SAVE_DATA_FUNCTION is not in the environment"
        puts error_msg
        return { success: false, error: error_msg }
      end
    
      begin
        payload = {
          'sourceType' => ENV['SOURCE_TYPE'],
          'version' => ENV['SOURCE_VERSION'],
          'table' => 'access',
          'data' => enhanced_data
        }
        
        uri = URI("#{ENV['OPENFAAS_GATEWAY']}/async-function/#{save_data_function}")
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(payload)
        
        response = http.request(request)
        
        if response.code == '202'
          return { success: true, error: nil }
        else
          error_msg = "Status #{response.code}: #{response.body}"
          puts error_msg
          return { success: false, error: error_msg }
        end
      rescue => e
        error_msg = "Error: #{e.message}"
        puts error_msg
        return { success: false, error: error_msg }
      end
    end
  end

  def update_execution(status = nil, total_objects = nil, completed_objects = nil, increment_completed_objects = nil, completed_at = nil)
    # Validation for dev environment
    if @run_local == "true"
      is_valid, error_msg = LocalTesting.validate_update_execution_params(status, total_objects, completed_objects, increment_completed_objects, completed_at)
      if !is_valid
        puts error_msg
        return { success: false, error: error_msg }
      else
        return { success: true, error: nil }
      end
    else
      app_update_function = ENV['APP_UPDATE_EXECUTION_FUNCTION']
      if !app_update_function
        error_msg = "APP_UPDATE_EXECUTION_FUNCTION is not in the environment"
        puts error_msg
        return { success: false, error: error_msg }
      end
    
      if @scan_execution_id && !@scan_execution_id.empty?
        execution_id = @scan_execution_id
        execution_type = 'scan'
      elsif @sync_execution_id && !@sync_execution_id.empty?
        execution_id = @sync_execution_id
        execution_type = 'sync'
      else
        error_msg = "Missing required field: either 'scanExecutionId' or 'syncExecutionId' must be provided"
        puts error_msg
        return { success: false, error: error_msg }
      end
      
      begin
        # Build payload with only provided arguments
        payload = {
          'type' => execution_type,
          'executionId' => execution_id
        }
        
        # Only include optional fields if they are provided (not nil)
        payload['status'] = status if !status.nil?
        payload['totalObjects'] = total_objects if !total_objects.nil?
        payload['completedObjects'] = completed_objects if !completed_objects.nil?
        payload['incrementCompletedObjects'] = increment_completed_objects if !increment_completed_objects.nil?
        payload['completedAt'] = completed_at if !completed_at.nil?
        
        uri = URI("#{ENV['OPENFAAS_GATEWAY']}/async-function/#{app_update_function}")
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(payload)
        
        response = http.request(request)
        
        if response.code == '202'
          return { success: true, error: nil }
        else
          error_msg = "Status #{response.code}: #{response.body}"
          puts error_msg
          return { success: false, error: error_msg }
        end
      rescue => e
        error_msg = "Error: #{e.message}"
        puts error_msg
        return { success: false, error: error_msg }
      end
    end
  end
end

def get_secrets(local_run = false)
  secrets = {}
  secrets_dir = '/var/openfaas/secrets/'
  
  begin
    Dir.entries(secrets_dir).each do |filename|
      next if filename == '.' || filename == '..'
      
      secret_path = File.join(secrets_dir, filename)
      next unless File.file?(secret_path)
      
      # Extract the key name based on local_run parameter
      if local_run
        # For local run, use the filename as-is (no scan ID removal)
        key_name = filename
      else
        # For non-local run, remove the last 9 characters (dash + 8 chars scan ID)
        if filename.length > 9 && filename[-9] == '-'
          key_name = filename[0...-9] # Remove last 9 characters (-abcd1234)
        else
          puts "Skipping secret file with unexpected format: #{filename}"
          next
        end
      end
      
      # Convert dash-separated to camelCase
      key_parts = key_name.split('-')
      if key_parts.length > 1
        # First part stays lowercase, subsequent parts are capitalized
        camel_key = key_parts[0] + key_parts[1..-1].map(&:capitalize).join('')
      else
        camel_key = key_parts[0]
      end
      
      # Read the secret content
      begin
        content = File.read(secret_path).strip
        secrets[camel_key] = content
        puts "Loaded secret: #{camel_key}"
      rescue => e
        puts "Error reading secret file #{filename}: #{e.message}"
      end
    end
  rescue => e
    puts "Error reading secrets directory: #{e.message}"
  end
  
  secrets
end

handler = Handler.new

before do
  @context = Context.new
  local_run = @context.run_local == "true"

  if local_run
    if !@context.config
      halt 400, {'Content-Type' => 'application/json'}, JSON.generate({error: "CONFIG is required when RUN_LOCAL is true"})
    end
    
    if !@context.function_type
      halt 400, {'Content-Type' => 'application/json'}, JSON.generate({error: "FUNCTION_TYPE is required when RUN_LOCAL is true"})
    end
    
    begin
      # Validate request body against config
      request_data = request.body.read
      request.body.rewind
      
      if request_data && !request_data.empty?
        request_json = JSON.parse(request_data)
        is_valid, error_msg = LocalTesting.validate_request_schema(@context.config, request_json, @context.function_type)
        if !is_valid
          halt 400, {'Content-Type' => 'application/json'}, JSON.generate({error: error_msg})
        end
      end
    rescue JSON::ParserError => e
      halt 400, {'Content-Type' => 'application/json'}, JSON.generate({error: "Invalid JSON in request body: #{e.message}"})
    end
  end

  # Load secrets from OpenFaaS secret files
  @context.secrets = get_secrets(local_run)

  # Parse execution IDs from request body
  begin
    request_data = request.body.read
    request.body.rewind
    
    if request_data && !request_data.empty?
      request_json = JSON.parse(request_data)
      @context.scan_execution_id = request_json['scanExecutionId'] if request_json['scanExecutionId']
      @context.sync_execution_id = request_json['syncExecutionId'] if request_json['syncExecutionId']
    end
  rescue JSON::ParserError
    # Ignore JSON parsing errors for execution IDs
  end

  if @context.secrets.empty?
    puts "Warning: No secrets loaded from secret files"
  else
    puts "Loaded #{@context.secrets.length} secrets from secret files"
  end
end

get '/*' do
  started_at = Time.now.utc.iso8601
  res, res_headers, status = handler.run request.body, request.env, @context
  completed_at = Time.now.utc.iso8601

  puts "Response data: #{res}"

  # Parse response if it's a hash with statusCode
  if res.is_a?(Hash) && res.key?(:statusCode)
    response_data = res
    
    # Add timestamps for successful responses
    if @context.function_type == "test-connection" && response_data[:statusCode] == 200
      response_data[:body] ||= {}
      response_data[:body][:startedAt] = started_at
      response_data[:body][:completedAt] = completed_at
    elsif @context.function_type == "access-scan" && response_data[:statusCode] == 200
      response_data[:body] ||= {}
      response_data[:body][:startedAt] = started_at
      response_data[:body][:completedAt] = completed_at
    end

    local_run = @context.run_local == "true"
    if local_run
      is_valid, error_msg = LocalTesting.validate_response(@context.function_type, response_data)
      if !is_valid
        response_data = @context.error_response(false, error_msg)
      end
    end

    # Return proper Sinatra response
    [response_data[:statusCode] || 200, {'Content-Type' => 'application/json'}, JSON.generate(response_data[:body])]
  else
    [status || 200, res_headers, res]
  end
end

post '/*' do
  started_at = Time.now.utc.iso8601
  res, res_headers, status = handler.run request.body, request.env, @context
  completed_at = Time.now.utc.iso8601

  puts "Response data: #{res}"

  # Parse response if it's a hash with statusCode
  if res.is_a?(Hash) && res.key?(:statusCode)
    response_data = res
    
    # Add timestamps for successful responses
    if @context.function_type == "test-connection" && response_data[:statusCode] == 200
      response_data[:body] ||= {}
      response_data[:body][:startedAt] = started_at
      response_data[:body][:completedAt] = completed_at
    elsif @context.function_type == "access-scan" && response_data[:statusCode] == 200
      response_data[:body] ||= {}
      response_data[:body][:startedAt] = started_at
      response_data[:body][:completedAt] = completed_at
    end

    local_run = @context.run_local == "true"
    if local_run
      is_valid, error_msg = LocalTesting.validate_response(@context.function_type, response_data)
      if !is_valid
        response_data = @context.error_response(false, error_msg)
      end
    end

    # Return proper Sinatra response
    [response_data[:statusCode] || 200, {'Content-Type' => 'application/json'}, JSON.generate(response_data[:body])]
  else
    [status || 200, res_headers, res]
  end
end

put '/*' do
  started_at = Time.now.utc.iso8601
  res, res_headers, status = handler.run request.body, request.env, @context
  completed_at = Time.now.utc.iso8601

  puts "Response data: #{res}"

  # Handle response similar to GET and POST
  if res.is_a?(Hash) && res.key?(:statusCode)
    response_data = res
    [response_data[:statusCode] || 200, {'Content-Type' => 'application/json'}, JSON.generate(response_data[:body])]
  else
    [status || 200, res_headers, res]
  end
end

delete '/*' do
  started_at = Time.now.utc.iso8601
  res, res_headers, status = handler.run request.body, request.env, @context
  completed_at = Time.now.utc.iso8601

  puts "Response data: #{res}"

  # Handle response similar to GET and POST
  if res.is_a?(Hash) && res.key?(:statusCode)
    response_data = res
    [response_data[:statusCode] || 200, {'Content-Type' => 'application/json'}, JSON.generate(response_data[:body])]
  else
    [status || 200, res_headers, res]
  end
end