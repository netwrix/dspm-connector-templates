#!/usr/bin/env python
from datetime import datetime, timezone
import requests
from flask import Flask, request, jsonify
from waitress import serve
import os
import json
import base64

from function import handler
from local_testing import validate_dev_data, validate_request_schema, validate_response, validate_update_execution_params

app = Flask(__name__)

class Event:
    def __init__(self):
        self.body = request.get_data()
        self.headers = request.headers
        self.method = request.method
        self.query = request.args
        self.path = request.path

class Context:
    def __init__(self):
        self.hostname = os.getenv('HOSTNAME', 'localhost')
        self.secrets = None
        self.scan_id = os.getenv('SCAN_ID')
        self.sync_id = os.getenv('SYNC_ID')
        self.scan_execution_id = None
        self.sync_execution_id = None
        self.run_local = os.getenv('RUN_LOCAL', 'false')
        self.config = json.loads(os.getenv('CONFIG', '{}'))
        self.function_type = os.getenv('FUNCTION_TYPE')

    def test_connection_success_response(self):
        return {
            "statusCode": 200,
            "body": {}
        }
    
    def access_scan_success_response(self):
        return {
            "statusCode": 200,
            "body": {}
        }
    
    def get_object_success_response(self, data):
        encoded_data = base64.b64encode(data).decode('utf-8')
        
        return {
            "statusCode": 200,
            "body": { "data": encoded_data }
        }

    def error_response(self, client_error, error_msg):
        if client_error:
            status_code = 400
        else:
            status_code = 500

        return {
            "statusCode": status_code,
            "body": {"error": error_msg}
        }
    
    def save_data(self, table, data, update_status=True):
        # Add appropriate IDs and timestamp based on operation type (scan vs sync)
        enhanced_data = []
        current_time = datetime.now(timezone.utc)

        local_run = self.run_local == "true"
        
        # Check if this is a sync operation
        is_sync_operation = self.sync_execution_id is not None and self.sync_execution_id != ""
        
        if is_sync_operation:
            # For sync operations - use ClickHouse DateTime format
            sync_id = "sync0001" if local_run else self.sync_id
            sync_execution_id = "sync-0002" if local_run else self.sync_execution_id
            sync_timestamp = current_time.strftime('%Y-%m-%d %H:%M:%S')
            for row in data:
                enhanced_row = {
                    'sync_id': sync_id,
                    'sync_execution_id': sync_execution_id,
                    'sync_timestamp': sync_timestamp,
                    **row  # Spread the original row data
                }
                enhanced_data.append(enhanced_row)
        else:
            # For scan operations
            scan_id = "scan0001" if local_run else self.scan_id
            scan_execution_id = "scan-0002" if local_run else self.scan_execution_id
            scanned_at = current_time.isoformat()
            
            for row in data:
                enhanced_row = {
                    'scan_id': scan_id,
                    'scan_execution_id': scan_execution_id,
                    'scanned_at': scanned_at,
                    **row  # Spread the original row data
                }
                enhanced_data.append(enhanced_row)
        
        # dev environment validation
        if local_run:
            is_valid, error_msg = validate_dev_data(self.config, table, enhanced_data)
            if not is_valid:
                print(error_msg, flush=True)
                return False, error_msg
            else:
                print(f"Saving {len(enhanced_data)} items to table", flush=True)
                print(f"Sample item: {json.dumps(enhanced_data[0], indent=2)}", flush=True)
                return True, None
        else:
            if os.getenv('SAVE_DATA_FUNCTION') == None:
                error_msg = "SAVE_DATA_FUNCTION is not in the environment"
                print(error_msg, flush=True)
                return False, error_msg
        
            try:
                payload = {
                    'sourceType': os.getenv('SOURCE_TYPE'),
                    'version': os.getenv('SOURCE_VERSION'),
                    'table': table,
                    'data': enhanced_data
                }
                
                response = requests.post(
                    f'{os.getenv("OPENFAAS_GATEWAY")}/async-function/{os.getenv("SAVE_DATA_FUNCTION")}',
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )
                
                if response.status_code == 202:
                    if update_status:
                        # Use appropriate field names based on operation type
                        if is_sync_operation:
                            self.update_execution(status='running', increment_completed_items=len(enhanced_data))
                        else:
                            self.update_execution(status='running', increment_completed_objects=len(enhanced_data))
                    return True, None
                else:
                    error_msg = f"Status {response.status_code}: {response.text}"
                    print(error_msg, flush=True)
                    return False, error_msg
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                print(error_msg, flush=True)
                return False, error_msg
    
    def update_execution(self, status=None, total_objects=None, completed_objects=None, increment_completed_objects=None, total_items=None, completed_items=None, increment_completed_items=None, completed_at=None):        
        # Validation for dev environment
        if self.run_local == "true":
            is_valid, error_msg = validate_update_execution_params(status, total_objects, completed_objects, increment_completed_objects, completed_at)
            if not is_valid:
                print(error_msg, flush=True)
                return False, error_msg
            else:
                return True, None
        else:
            if os.getenv('APP_UPDATE_EXECUTION_FUNCTION') == None:
                error_msg = "APP_UPDATE_EXECUTION_FUNCTION is not in the environment"
                print(error_msg, flush=True)
                return False, error_msg
        
            if self.scan_execution_id != "" and self.scan_execution_id != None:
                execution_id = self.scan_execution_id
                execution_type = 'scan'
            elif self.sync_execution_id != "" and self.sync_execution_id != None:
                execution_id = self.sync_execution_id
                execution_type = 'sync'
            else:
                error_msg = "Missing required field: either 'scanExecutionId' or 'syncExecutionId' must be provided"
                print(error_msg, flush=True)
                return False, error_msg
            
            try:
                # Build payload with only provided arguments
                payload = {
                    'type': execution_type,
                    'executionId': execution_id
                }
                
                # Only include optional fields if they are provided (not None)
                if status is not None:
                    payload['status'] = status
                
                # Handle both Items (sync) and Objects (scan) parameter naming
                # For total count
                total_value = None
                if total_items is not None:
                    total_value = total_items
                elif total_objects is not None:
                    total_value = total_objects
                
                if total_value is not None:
                    if execution_type == 'sync':
                        payload['totalItems'] = total_value
                    else:
                        payload['totalObjects'] = total_value
                
                # For completed count
                completed_value = None
                if completed_items is not None:
                    completed_value = completed_items
                elif completed_objects is not None:
                    completed_value = completed_objects
                
                if completed_value is not None:
                    if execution_type == 'sync':
                        payload['completedItems'] = completed_value
                    else:
                        payload['completedObjects'] = completed_value
                
                # For increment completed count
                increment_value = None
                if increment_completed_items is not None:
                    increment_value = increment_completed_items
                elif increment_completed_objects is not None:
                    increment_value = increment_completed_objects
                
                if increment_value is not None:
                    if execution_type == 'sync':
                        payload['incrementCompletedItems'] = increment_value
                    else:
                        payload['incrementCompletedObjects'] = increment_value
                
                if completed_at is not None:
                    payload['completedAt'] = completed_at
                
                response = requests.post(
                    f'{os.getenv("OPENFAAS_GATEWAY")}/function/{os.getenv("APP_UPDATE_EXECUTION_FUNCTION")}',
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )
                
                if response.status_code == 202:
                    return True, None
                else:
                    error_msg = f"Status {response.status_code}: {response.text}"
                    print(error_msg, flush=True)
                    return False, error_msg
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                print(error_msg, flush=True)
                return False, error_msg

def get_secrets(local_run=False):
    """Read all secrets from OpenFaaS secret mount path and build a dictionary"""
    secrets_dict = {}
    secrets_dir = '/var/openfaas/secrets/'
    
    try:
        # List all files in the secrets directory
        for filename in os.listdir(secrets_dir):
            secret_path = os.path.join(secrets_dir, filename)
            
            # Skip directories and non-files
            if not os.path.isfile(secret_path):
                continue
            
            # Extract the key name based on local_run parameter
            if local_run:
                # For local run, use the filename as-is (no scan ID removal)
                key_name = filename
            else:
                # For non-local run, remove the last 9 characters (dash + 8 chars scan ID)
                if len(filename) > 9 and filename[-9:-8] == '-':
                    key_name = filename[:-9]  # Remove last 9 characters (-abcd1234)
                else:
                    print(f"Skipping secret file with unexpected format: {filename}", flush=True)
                    continue
            
            # Convert dash-separated to camelCase
            key_parts = key_name.split('-')
            if len(key_parts) > 1:
                # First part stays lowercase, subsequent parts are capitalized
                camel_key = key_parts[0] + ''.join(word.capitalize() for word in key_parts[1:])
            else:
                camel_key = key_parts[0]
            
            # Read the secret content
            try:
                with open(secret_path, 'r') as f:
                    content = f.read().strip()
                    secrets_dict[camel_key] = content
                    print(f"Loaded secret: {camel_key}", flush=True)
            except Exception as e:
                print(f"Error reading secret file {filename}: {str(e)}", flush=True)
    
    except Exception as e:
        print(f"Error reading secrets directory: {str(e)}", flush=True)
    
    return secrets_dict
    
def format_status_code(resp):
    if 'statusCode' in resp:
        return resp['statusCode']
    
    return 200

def format_body(resp):
    if 'body' not in resp:
        return ""
    elif type(resp['body']) == dict:
        return jsonify(resp['body'])
    else:
        return str(resp['body'])

def format_headers(resp):
    if 'headers' not in resp:
        return []
    elif type(resp['headers']) == dict:
        headers = []
        for key in resp['headers'].keys():
            header_tuple = (key, resp['headers'][key])
            headers.append(header_tuple)
        return headers
    
    return resp['headers']

def format_response(resp):
    if resp == None:
        return ('', 200)
    
    if type(resp) is dict:
        statusCode = format_status_code(resp)
        body = format_body(resp)
        headers = format_headers(resp)

        return (body, statusCode, headers)

    return resp

@app.route('/', defaults={'path': ''}, methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
def call_handler(path):
    event = Event()
    context = Context()

    if context.run_local == "true":
        local_run = True
    else:
        local_run = False

    if local_run:
        if context.config is None:
            return jsonify({"error": "CONFIG is required when RUN_LOCAL is true"}), 400
        
        if context.function_type is None:
            return jsonify({"error": "FUNCTION_TYPE is required when RUN_LOCAL is true"}), 400
        
        try:
            # Validate request body against config
            request_data = json.loads(event.body)
            is_valid, error_msg = validate_request_schema(context.config, request_data, context.function_type)
            if not is_valid:
                return jsonify({"error": error_msg}), 400
            
        except json.JSONDecodeError as e:
            return jsonify({"error": f"Invalid JSON in CONFIG: {str(e)}"}), 400
        except Exception as e:
            return jsonify({"error": f"Invalid JSON in request body: {str(e)}"}), 400

    # Load secrets from OpenFaaS secret files
    context.secrets = get_secrets(local_run)

    request_data = json.loads(event.body)
    context.scan_execution_id = request_data.get('scanExecutionId')
    context.sync_execution_id = request_data.get('syncExecutionId')
    
    if not context.secrets:
        print("Warning: No secrets loaded from secret files", flush=True)
    else:
        print(f"Loaded {len(context.secrets)} secrets from secret files", flush=True)
    
    started_at = datetime.now(timezone.utc).isoformat()

    if context.function_type == "access-scan":
        context.update_execution(status='running')
    elif context.function_type == "sync":
        context.update_execution(status='running')

    response_data = handler.handle(event, context)
    completed_at = datetime.now(timezone.utc).isoformat()

    if context.function_type == "test-connection" and response_data['statusCode'] == 200:
        response_data['body']['startedAt'] = started_at
        response_data['body']['completedAt'] = completed_at
    elif context.function_type == "access-scan":
        if response_data['statusCode'] == 200:
            response_data['body']['startedAt'] = started_at
            response_data['body']['completedAt'] = completed_at
            context.update_execution(status='completed', completed_at=completed_at)
        else:
            context.update_execution(status='failed', completed_at=completed_at)
    elif context.function_type == "sync":
        # Handle sync responses and update sync execution status
        if response_data['statusCode'] == 200:
            if 'body' in response_data and isinstance(response_data['body'], dict):
                response_data['body']['startedAt'] = started_at
                response_data['body']['completedAt'] = completed_at
            context.update_execution(status='completed', completed_at=completed_at)
        else:
            context.update_execution(status='failed', completed_at=completed_at)
    
    if local_run:
        is_valid, error_msg = validate_response(context.function_type, response_data)
        if not is_valid:
            response_data = context.error_response(False, error_msg)

    resp = format_response(response_data)
    return resp

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
