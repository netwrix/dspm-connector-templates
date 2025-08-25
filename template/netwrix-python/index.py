#!/usr/bin/env python
import requests
from flask import Flask, request, jsonify
from waitress import serve
import os
import json

from function import handler
from local_testing import validate_dev_data

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
        self.environment = os.getenv('ENVIRONMENT', 'PROD')
        self.config = os.getenv('CONFIG')
    
    def save_data(self, table, data):
        if os.getenv('SAVE_DATA_FUNCTION') == None:
            error_msg = "SAVE_DATA_FUNCTION is not in the environment"
            print(error_msg, flush=True)
            return False, error_msg
        
        # dev environment validation
        if self.environment == "dev":
            is_valid, error_msg = validate_dev_data(self.config, table, data)
            if not is_valid:
                print(error_msg, flush=True)
                return False, error_msg
        else:
            try:
                payload = {
                    'sourceType': os.getenv('SOURCE_TYPE'),
                    'version': os.getenv('SOURCE_VERSION'),
                    'table': table,
                    'data': data
                }
                
                response = requests.post(
                    f'{os.getenv("OPENFAAS_GATEWAY")}/async-function/{os.getenv("SAVE_DATA_FUNCTION")}',
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
    
    def update_execution(self, status=None, total_objects=None, completed_objects=None, increment_completed_objects=None, completed_at=None):
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
            if total_objects is not None:
                payload['totalObjects'] = total_objects
            if completed_objects is not None:
                payload['completedObjects'] = completed_objects
            if increment_completed_objects is not None:
                payload['incrementCompletedObjects'] = increment_completed_objects
            if completed_at is not None:
                payload['completedAt'] = completed_at
            
            response = requests.post(
                f'{os.getenv("OPENFAAS_GATEWAY")}/async-function/{os.getenv("APP_UPDATE_EXECUTION_FUNCTION")}',
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

def get_secrets():
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
            
            # Extract the key name by removing the last 9 characters (dash + 8 chars)
            if len(filename) > 9 and filename[-9:-8] == '-':
                key_name = filename[:-9]  # Remove last 9 characters (-abcd1234)
                
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
            else:
                print(f"Skipping secret file with unexpected format: {filename}", flush=True)
    
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
    
    # Load secrets from OpenFaaS secret files
    context.secrets = get_secrets()

    request_data = json.loads(event.body)
    context.scan_execution_id = request_data.get('scanExecutionId')
    context.sync_execution_id = request_data.get('syncExecutionId')
    
    if not context.secrets:
        print("Warning: No secrets loaded from secret files", flush=True)
    else:
        print(f"Loaded {len(context.secrets)} secrets from secret files", flush=True)
    
    response_data = handler.handle(event, context)
    
    resp = format_response(response_data)
    return resp

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
