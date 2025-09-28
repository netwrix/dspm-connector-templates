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

        scan_id = os.getenv("SCAN_ID")
        sync_id = os.getenv("SYNC_ID")
        if (scan_id is None and sync_id is None) or (scan_id is not None and sync_id is not None):
            raise ValueError("Exactly one of SCAN_ID or SYNC_ID must be set, but got SCAN_ID={!r}, SYNC_ID={!r}".format(scan_id, sync_id))

        self.operation_id: str = scan_id if scan_id is not None else sync_id
            
        self.operation_execution_id: str | None = None
        self.run_local: bool = os.getenv("RUN_LOCAL", "false").lower() == "true"
        self.function_type: str | None = os.getenv("FUNCTION_TYPE")
        self.connector_name: str | None = os.getenv("CONNECTOR_NAME")
        self.connector_version: str | None = os.getenv("CONNECTOR_VERSION")
        self.save_data_function_host: str | None = os.getenv("SAVE_DATA_FUNCTION_HOST")
        self.app_update_execution_function_host: str | None = os.getenv("APP_UPDATE_EXECUTION_FUNCTION_HOST")
        self.is_test_connection: bool = self.function_type == "test-connection"
        self.is_access_scan: bool = self.function_type == "access-scan"
        self.is_get_object: bool = self.function_type == "get-object"
        self.is_sync: bool = self.function_type == "sync"
        self.is_scan: bool = bool(os.getenv("SCAN_ID"))
        self.operation_type: str | None = "sync" if self.is_sync else "scan" if self.is_scan else None


    def success_response(self, data=None):
      return {
          "statusCode": 200,
          "body": {"data": base64.b64encode(data).decode("utf-8")} if data else {}
      }


    def error_response(self, client_error, error_msg):
      return {"statusCode": 400 if client_error else 500, "body": {"error": error_msg}}


    def save_data(self, table, data, update_status=True):
        # Add appropriate IDs and timestamp based on operation type (scan vs sync)
        enhanced_data = []
        current_time = datetime.now(UTC).isoformat()

        for row in data:
            enhanced_row = {
                f"{self.operation_type}_id": self.operation_id,
                f"{self.operation_type}_execution_id": self.operation_execution_id,
                f"{'scanned' if self.operation_type == 'scan' else 'synced'}_at": current_time,
                **row,  # Spread the original row data
            }
            enhanced_data.append(enhanced_row)

        try:
            payload = {
                "sourceType": self.connector_name,
                "version": self.connector_version,
                "table": table,
                "data": enhanced_data,
            }

            response = requests.post(
                self.save_data_function_host,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            is_success = response.status_code == 202 or (self.run_local and response.status_code == 200)
            if is_success:
                if update_status:
                    self.__update_execution(
                        status="running",
                        increment_completed_objects=len(enhanced_data),
                    )
                return True, None

            error_msg = f"Status {response.status_code}: {response.text}"
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(error_msg, flush=True)
            return False, error_msg


    def __update_execution(self,status=None,total_objects=None,completed_objects=None,increment_completed_objects=None,completed_at=None):
        try:
            # Build payload with only provided arguments
            payload = {"type": self.operation_type, "executionId": self.operation_execution_id}

            # Only include optional fields if they are provided (not None)
            if status is not None:
                payload["status"] = status

            # Handle both Items (sync) and Objects (scan) parameter naming
            # For total count
            object_type = "Items" if self.is_sync else "Objects"

            if total_objects is not None:
                payload[f"total{object_type}"] = total_objects

            if completed_objects is not None:
                payload[f"completed{object_type}"] = completed_objects

            if increment_completed_objects is not None:
                payload[f"incrementCompleted{object_type}"] = increment_completed_objects

            if completed_at is not None:
                payload["completedAt"] = completed_at

            response = requests.post(
                self.app_update_execution_function_host,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            is_success = response.status_code == 202 or (self.run_local and response.status_code == 200)
            if is_success:
                return True, None
            error_msg = f"Status {response.status_code}: {response.text}"
            print(error_msg, flush=True)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(error_msg, flush=True)
            return False, error_msg


def get_secrets(context) -> dict[str, str]:
    secrets_dict: dict[str, str] = {}
    secrets_dir = "/var/openfaas/secrets/"

    try:
        for filename in os.listdir(secrets_dir):
            secret_path = os.path.join(secrets_dir, filename)

            if not os.path.isfile(secret_path): continue
            if context.run_local: key_name = filename
            else:
                parts = filename.rsplit("-", 1)
                if len(parts) != 2 or len(parts[1]) != 8:
                    continue
                key_name = parts[0]

            camel_key = to_camel_case(key_name)
            try:
                with open(secret_path) as f:
                    secrets_dict[camel_key] = f.read().strip()
            except Exception as e:
                print(f"Error reading secret file {filename}: {str(e)}", flush=True)

    except Exception as e:
        print(f"Error accessing secrets directory: {str(e)}", flush=True)

    return secrets_dict


def to_camel_case(key_name: str) -> str:
    parts = key_name.split("-")
    return parts[0] + "".join(word.capitalize() for word in parts[1:])


def format_status_code(resp):
    return resp.get("statusCode", 200)


def format_body(resp):
    body = resp.get("body", "")
    if isinstance(body, dict):
        return jsonify(body)
    return str(body)


def format_headers(resp):
    headers = resp.get("headers", [])
    if isinstance(headers, dict):
        return [(key, value) for key, value in headers.items()]
    return headers


def format_response(resp):
    if resp is None:
        return ("", 200)
    elif isinstance(resp, dict):
        return (format_body(resp), format_status_code(resp), format_headers(resp))
    return resp


@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
def call_handler(path: str):
    event = Event()
    context = Context()
    context.secrets = get_secrets(context)
    context.operation_execution_id = json.loads(event.body).get("scanExecutionId") or json.loads(event.body).get("syncExecutionId")
    started_at = datetime.now(UTC).isoformat()

    if context.is_access_scan or context.is_sync:
        context._Context__update_execution(status="running")

    response_data = handler.handle(event, context)
    completed_at = datetime.now(UTC).isoformat()

    success = response_data["statusCode"] == 200
    if success and (context.is_test_connection or context.is_access_scan or context.is_sync):
        response_data["body"].update({"startedAt": started_at, "completedAt": completed_at})

    if context.is_access_scan or context.is_sync:
        status = "completed" if success else "failed"
        context._Context__update_execution(status=status, completed_at=completed_at)

    return format_response(response_data)


if __name__ == "__main__":
    is_debug = os.getenv("DEBUG_MODE", "false").lower() == "true"
    debug_host = os.getenv("DEBUG_HOST", "0.0.0.0")
    debug_port = int(os.getenv("DEBUG_PORT", 5678))

    if is_debug:
        try:
            import debugpy

            debugpy.listen((debug_host, debug_port))
            print("Debugger listening on {}:{}".format(debug_host, debug_port))
            debugpy.wait_for_client()
        except ImportError:
            app.logger.error("Could not find debugpy module, continuing without debugger.")
        except Exception as e:
            app.logger.error(
                f"Connection to debugger failed: {str(e)}. Ensure your debugger is configured correctly or set DEBUG_MODE to false."
            )

        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=True)
    else:
        serve(app, host="0.0.0.0", port=5000)
