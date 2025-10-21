#!/usr/bin/env python
import base64
import json
import os
from datetime import UTC, datetime
from logging.config import dictConfig

import requests
from flask import Flask, jsonify, request
from waitress import serve

from function import handler


dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
            }
        },
        "root": {"level": os.getenv("LOG_LEVEL", "INFO").upper(), "handlers": ["wsgi"]},
    }
)

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
        self.secrets: dict[str, str] | None = None
        self.scan_id: str | None = os.getenv("SCAN_ID")
        self.sync_id: str | None = os.getenv("SYNC_ID")
        self.scan_execution_id: str | None = None
        self.sync_execution_id: str | None = None
        self.run_local: str = os.getenv("RUN_LOCAL", "false")
        self.function_type: str | None = os.getenv("FUNCTION_TYPE")

    def test_connection_success_response(self):
        return {"statusCode": 200, "body": {}}

    def access_scan_success_response(self):
        return {"statusCode": 200, "body": {}}

    def get_object_success_response(self, data):
        encoded_data = base64.b64encode(data).decode("utf-8")

        return {"statusCode": 200, "body": {"data": encoded_data}}

    def error_response(self, client_error, error_msg):
        status_code = 400 if client_error else 500

        return {"statusCode": status_code, "body": {"error": error_msg}}

    def save_data(self, table, data, update_status=True):
        # Add appropriate IDs and timestamp based on operation type (scan vs sync)
        enhanced_data = []
        current_time = datetime.now(UTC).isoformat()

        local_run = self.run_local == "true"

        # Check if this is a sync operation
        is_sync_operation = self.function_type == "sync"

        if is_sync_operation:
            # For sync operations - use ClickHouse DateTime format
            sync_id = self.sync_id
            sync_execution_id = self.sync_execution_id
            synced_at = current_time
            for row in data:
                enhanced_row = {
                    "sync_id": sync_id,
                    "sync_execution_id": sync_execution_id,
                    "synced_at": synced_at,
                    **row,  # Spread the original row data
                }
                enhanced_data.append(enhanced_row)
        else:
            # For scan operations
            scan_id = self.scan_id
            scan_execution_id = self.scan_execution_id
            scanned_at = current_time

            for row in data:
                enhanced_row = {
                    "scan_id": scan_id,
                    "scan_execution_id": scan_execution_id,
                    "scanned_at": scanned_at,
                    **row,  # Spread the original row data
                }
                enhanced_data.append(enhanced_row)

        try:
            payload = {
                "sourceType": os.getenv("SOURCE_TYPE"),
                "version": os.getenv("SOURCE_VERSION"),
                "table": table,
                "data": enhanced_data,
            }

            if local_run:
                ## call to local docker container function
                response = requests.post(
                    f"http://{os.getenv('SAVE_DATA_FUNCTION', 'data-ingestion')}:8080",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
            else:
                response = requests.post(
                    f"{os.getenv('OPENFAAS_GATEWAY')}/async-function/{os.getenv('SAVE_DATA_FUNCTION')}",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )

            if response.status_code == 202 or (local_run and response.status_code == 200):
                if update_status:
                    self.update_execution(
                        status="running",
                        increment_completed_objects=len(enhanced_data),
                    )
                return True, None
            error_msg = f"Status {response.status_code}: {response.text}"
            print(error_msg, flush=True)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(error_msg, flush=True)
            return False, error_msg

    def update_execution(
        self,
        status=None,
        total_objects=None,
        completed_objects=None,
        increment_completed_objects=None,
        completed_at=None,
    ):

        local_run = self.run_local == "true"

        if self.function_type == "sync":
            execution_id = self.sync_execution_id
            execution_type = "sync"
        else:
            execution_id = self.scan_execution_id
            execution_type = "scan"

        try:
            # Build payload with only provided arguments
            payload = {"type": execution_type, "executionId": execution_id}

            # Only include optional fields if they are provided (not None)
            if status is not None:
                payload["status"] = status

            # Both scan and sync operations will use the *objects parameters when updating the execution status.
            # app-update-execution function expects the parameter to be named totalObjects
            # and it will use the correct column name depending on if it's a scan or sync operation.
            if total_objects is not None:
                payload["totalObjects"] = total_objects

            if completed_objects is not None:
                payload["completedObjects"] = completed_objects

            if increment_completed_objects is not None:
                payload["incrementCompletedObjects"] = increment_completed_objects

            if completed_at is not None:
                payload["completedAt"] = completed_at

            if local_run:
                response = requests.post(
                    f"http://{os.getenv('SAVE_DATA_FUNCTION', 'data-ingestion')}:8080",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
            else:
                response = requests.post(
                    f"{os.getenv('OPENFAAS_GATEWAY')}/function/{os.getenv('APP_UPDATE_EXECUTION_FUNCTION')}",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )

            if response.status_code == 202 or (local_run and response.status_code == 200):
                return True, None
            error_msg = f"Status {response.status_code}: {response.text}"
            print(error_msg, flush=True)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(error_msg, flush=True)
            return False, error_msg


def get_secrets(local_run: bool = False) -> dict[str, str]:
    """Read all secrets from OpenFaaS secret mount path and build a dictionary"""
    secrets_dict: dict[str, str] = {}
    secrets_dir = "/var/openfaas/secrets/"

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
                if len(filename) > 9 and filename[-9:-8] == "-":
                    key_name = filename[:-9]  # Remove last 9 characters (-abcd1234)
                else:
                    print(
                        f"Skipping secret file with unexpected format: {filename}",
                        flush=True,
                    )
                    continue

            # Convert dash-separated to camelCase
            key_parts = key_name.split("-")
            if len(key_parts) > 1:
                # First part stays lowercase, subsequent parts are capitalized
                camel_key = key_parts[0] + "".join(word.capitalize() for word in key_parts[1:])
            else:
                camel_key = key_parts[0]

            # Read the secret content
            try:
                with open(secret_path) as f:
                    content = f.read().strip()
                    secrets_dict[camel_key] = content
                    print(f"Loaded secret: {camel_key}", flush=True)
            except Exception as e:
                print(f"Error reading secret file {filename}: {str(e)}", flush=True)

    except Exception as e:
        print(f"Error reading secrets directory: {str(e)}", flush=True)

    return secrets_dict


def format_status_code(resp):
    if "statusCode" in resp:
        return resp["statusCode"]

    return 200


def format_body(resp):
    if "body" not in resp:
        return ""
    if type(resp["body"]) is dict:
        return jsonify(resp["body"])
    return str(resp["body"])


def format_headers(resp):
    if "headers" not in resp:
        return []
    if type(resp["headers"]) is dict:
        headers = []
        for key in resp["headers"]:
            header_tuple = (key, resp["headers"][key])
            headers.append(header_tuple)
        return headers

    return resp["headers"]


def format_response(resp):
    if resp is None:
        return ("", 200)

    if type(resp) is dict:
        status_code = format_status_code(resp)
        body = format_body(resp)
        headers = format_headers(resp)

        return (body, status_code, headers)

    return resp


@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
def call_handler(path: str):
    event = Event()
    context = Context()

    local_run = context.run_local == "true"

    # Load secrets from OpenFaaS secret files
    context.secrets = get_secrets(local_run)

    request_data = json.loads(event.body)
    context.scan_execution_id = request_data.get("scanExecutionId")
    context.sync_execution_id = request_data.get("syncExecutionId")

    if not context.secrets:
        print("Warning: No secrets loaded from secret files", flush=True)
    else:
        print(f"Loaded {len(context.secrets)} secrets from secret files", flush=True)

    started_at = datetime.now(UTC).isoformat()

    if context.function_type == "access-scan" or context.function_type == "sync":
        context.update_execution(status="running")

    response_data = handler.handle(event, context)
    completed_at = datetime.now(UTC).isoformat()

    if context.function_type == "test-connection" and response_data["statusCode"] == 200:
        response_data["body"]["startedAt"] = started_at
        response_data["body"]["completedAt"] = completed_at
    elif context.function_type == "access-scan" or context.function_type == "sync":
        if response_data["statusCode"] == 200:
            response_data["body"]["startedAt"] = started_at
            response_data["body"]["completedAt"] = completed_at
            context.update_execution(status="completed", completed_at=completed_at)
        else:
            context.update_execution(status="failed", completed_at=completed_at)

    return format_response(response_data)


if __name__ == "__main__":
    if os.getenv("DEBUG_MODE", "false").lower() == "true":
        try:
            import debugpy

            debugpy.listen((os.getenv("DEBUG_HOST", "0.0.0.0"), int(os.getenv("DEBUG_PORT", 5678))))
            print("Debugger listening on {}:{}".format(os.getenv("DEBUG_HOST", "0.0.0.0"), os.getenv("DEBUG_PORT", 5678)))
            debugpy.wait_for_client()
        except ImportError:
            app.logger.error("debugpy module not found, continuing without debugger")
        except Exception as e:
            app.logger.error(
                f"Connection to debugger failed: {str(e)}. Ensure your debugger is configured correctly or set DEBUG_MODE to false"
            )

        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=False)
    else:
        serve(app, host="0.0.0.0", port=5000)
