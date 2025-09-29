#!/usr/bin/env python
import base64
import json
import logging
import os
from datetime import UTC, datetime
from logging.config import dictConfig

import requests
from flask import Flask, jsonify, request
from waitress import serve

from function import handler

logger = logging.getLogger(__name__)


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
        self.function_type: str | None = os.getenv("FUNCTION_TYPE")
        scan_id = os.getenv("SCAN_ID")
        sync_id = os.getenv("SYNC_ID")

        # Test connection functions don't need scan_id or sync_id
        if self.function_type != "test-connection" and ((scan_id is None and sync_id is None) or (scan_id is not None and sync_id is not None)):
            raise ValueError(f"Exactly one of SCAN_ID or SYNC_ID must be set, but got SCAN_ID={scan_id}, SYNC_ID={sync_id}")

        self.operation_id: str | None = scan_id if scan_id is not None else sync_id
        self.operation_execution_id: str | None = None
        self.run_local: bool = os.getenv("RUN_LOCAL", "false").lower() == "true"
        self.connector_name: str | None = os.getenv("CONNECTOR_NAME")
        self.connector_version: str | None = os.getenv("CONNECTOR_VERSION")
        self.save_data_function_host: str | None = os.getenv("SAVE_DATA_FUNCTION_HOST")
        self.app_update_execution_function_host: str | None = os.getenv("APP_UPDATE_EXECUTION_FUNCTION_HOST")
        self._validate_required_env_vars()

        self.is_test_connection: bool = self.function_type == "test-connection"
        self.is_access_scan: bool = self.function_type == "access-scan"
        self.is_get_object: bool = self.function_type == "get-object"
        self.is_sync: bool = self.function_type == "sync"
        self.is_scan: bool = bool(os.getenv("SCAN_ID"))
        self.operation_type: str | None = "sync" if self.is_sync else "scan" if self.is_scan else None

    def _validate_required_env_vars(self):
        required_vars = {
            "FUNCTION_TYPE": self.function_type,
            "CONNECTOR_NAME": self.connector_name,
            "CONNECTOR_VERSION": self.connector_version,
            "SAVE_DATA_FUNCTION_HOST": self.save_data_function_host,
            "APP_UPDATE_EXECUTION_FUNCTION_HOST": self.app_update_execution_function_host,
        }

        missing = [name for name, value in required_vars.items() if value is None]
        if missing:
            raise ValueError(f"Required environment variables not set: {', '.join(missing)}")
        logger.debug("Environment variables validated successfully")

    def success_response(self, data=None):
        if data is None:
            return {"statusCode": 200, "body": {}}

        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = json.dumps(data).encode("utf-8")

        return {"statusCode": 200, "body": {"data": base64.b64encode(data_bytes).decode("utf-8")}}

    def error_response(self, client_error, error_msg):
        return {"statusCode": 400 if client_error else 500, "body": {"error": error_msg}}

    def save_data(self, table, data, update_status=True):
        logger.info(f"Saving {len(data)} records to table '{table}'")
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

            logger.debug(f"Sending payload to {self.save_data_function_host}: {len(enhanced_data)} records")
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
            logger.error(error_msg)
            return False, error_msg

    def __update_execution(
        self,
        status=None,
        total_objects=None,
        completed_objects=None,
        increment_completed_objects=None,
        completed_at=None,
    ):
        try:
            logger.debug(f"Updating execution status to '{status}' for {self.operation_type}")
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
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg


def get_secrets(context) -> dict[str, str]:
    secrets_dict: dict[str, str] = {}
    secrets_dir = "/var/openfaas/secrets/"

    try:
        if not os.path.exists(secrets_dir):
            logger.warning(f"Secrets directory does not exist: {secrets_dir}")
            return {}

        for filename in os.listdir(secrets_dir):
            secret_path = os.path.join(secrets_dir, filename)

            if not os.path.isfile(secret_path):
                continue
            if context.run_local:
                key_name = filename
            else:
                parts = filename.rsplit("-", 1)
                if len(parts) != 2 or len(parts[1]) != 8:
                    logger.warning(f"Skipping secret file with unexpected format: {filename}")
                    continue
                key_name = parts[0]

            camel_key = to_camel_case(key_name)
            try:
                with open(secret_path) as f:
                    secrets_dict[camel_key] = f.read().strip()
            except Exception as e:
                logger.error(f"Error reading secret file {filename}: {str(e)}")

    except Exception as e:
        logger.error(f"Error accessing secrets directory: {str(e)}")

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
    if isinstance(resp, dict):
        return (format_body(resp), format_status_code(resp), format_headers(resp))
    return resp


@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
def call_handler(path: str):
    try:
        event = Event()
        context = Context()
        logger.info(f"Starting {context.function_type} operation {context.operation_id}")
        context.secrets = get_secrets(context)
        logger.debug(f"Loaded {len(context.secrets) if context.secrets else 0} secrets")
    except ValueError as e:  # Config errors from Context validation
        logger.error(f"Configuration error: {e}")
        return {"statusCode": 500, "body": {"error": str(e)}}, 500
    except Exception as e:  # Unexpected errors
        logger.error(f"Unexpected error during initialization: {e}")
        return {"statusCode": 500, "body": {"error": "Internal server error"}}, 500
    try:
        body_data = json.loads(event.body)
        context.operation_execution_id = body_data.get("scanExecutionId") or body_data.get("syncExecutionId")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(f"Invalid request body: {e}")
        return {"statusCode": 400, "body": {"error": "Invalid JSON in request body"}}, 400
    started_at = datetime.now(UTC).isoformat()

    if context.is_access_scan or context.is_sync:
        context.__update_execution(status="running")

    try:
        response_data = handler.handle(event, context)
    except Exception as e:
        logger.error(f"Handler execution failed: {e}")
        response_data = {"statusCode": 500, "body": {"error": "Handler execution failed"}}
    completed_at = datetime.now(UTC).isoformat()

    success = response_data["statusCode"] == 200 if response_data is not None else False
    logger.info(
        f"Operation {context.operation_id} completed with status {response_data['statusCode'] if response_data else 'None'}"
    )
    if success and (context.is_test_connection or context.is_access_scan or context.is_sync):
        response_data["body"].update({"startedAt": started_at, "completedAt": completed_at})

    if context.is_access_scan or context.is_sync:
        status = "completed" if success else "failed"
        context.__update_execution(status=status, completed_at=completed_at)

    return format_response(response_data)


if __name__ == "__main__":
    is_debug = os.getenv("DEBUG_MODE", "false").lower() == "true"
    debug_library = os.getenv("DEBUG_LIBRARY", "debugpy").lower()
    debug_host = os.getenv("DEBUG_HOST", "0.0.0.0")
    debug_port = int(os.getenv("DEBUG_PORT", 5678))

    if is_debug:
        try:
            if debug_library == "debugpy":
                import debugpy # type: ignore # noqa

                debugpy.listen((debug_host, debug_port)) # type: ignore # noqa
            elif debug_library == "pycharm":
                import pydevd_pycharm # type: ignore # noqa

                pydevd_pycharm.settrace(debug_host, port=debug_port, stdoutToServer=True, stderrToServer=True)
            else:
                app.logger.error(f"Unknown debug library: {debug_library}. Supported: debugpy, pycharm.")
        except Exception as e:
            app.logger.error(
                f"Connection to debugger failed: {str(e)}. Ensure your debugger is configured correctly or set DEBUG_MODE to false."
            )

        logger.debug(f"Using {debug_library} debugger on {debug_host}:{debug_port}.")
        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=False)
    else:
        serve(app, host="0.0.0.0", port=5000)
