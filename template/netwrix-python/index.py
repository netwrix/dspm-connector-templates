#!/usr/bin/env python
import base64
import json
import logging
import os
from datetime import UTC, datetime
from logging.config import dictConfig
from typing import Final

import requests
from flask import Flask, jsonify, request
from opentelemetry import metrics, trace
from opentelemetry.trace.status import StatusCode
from waitress import serve

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

SOURCE_TYPE: Final = os.getenv("SOURCE_TYPE", "internal")
FUNCTION_TYPE: Final = os.getenv("FUNCTION_TYPE", "netwrix")
SERVICE_NAME: Final = os.getenv("SERVICE_NAME", f"{SOURCE_TYPE}-{FUNCTION_TYPE}")
app = Flask(SERVICE_NAME)


def setup_opentelemetry(app: object | None = None) -> None:
    """
    Initialize OpenTelemetry instrumentation for traces, metrics, and logs.

    Returns:
        bool: True if setup succeeded, False otherwise
    """
    if os.getenv("OTEL_ENABLED", "true").lower() != "true":
        logging.info("OpenTelemetry disabled via OTEL_ENABLED environment variable")
        return

    from opentelemetry._logs import set_logger_provider
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    try:
        otel_endpoint = os.getenv(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector.access-analyzer.svc.cluster.local:4318"
        )

        resource = Resource.create(
            {
                "service.name": SERVICE_NAME,
                "service.namespace": "dspm-functions",
                "deployment.environment": os.getenv("ENVIRONMENT", "development"),
            }
        )

        trace_provider = TracerProvider(resource=resource)
        trace_processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otel_endpoint}/v1/traces"))
        trace_provider.add_span_processor(trace_processor)
        trace.set_tracer_provider(trace_provider)

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=f"{otel_endpoint}/v1/metrics"), export_interval_millis=60000
        )
        metric_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(metric_provider)

        logger_provider = LoggerProvider(resource=resource)
        log_processor = BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{otel_endpoint}/v1/logs"))
        logger_provider.add_log_record_processor(log_processor)
        set_logger_provider(logger_provider)

        handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
        logging.getLogger().addHandler(handler)

        if app is not None:
            FlaskInstrumentor().instrument_app(app)

        RequestsInstrumentor().instrument()

        logging.info("OpenTelemetry initialized")

    except Exception:
        logging.exception("Failed to initialize OpenTelemetry")


def get_tracer(name: str):
    """Get a tracer for manual instrumentation"""
    return trace.get_tracer(name)


def get_meter(name: str):
    """Get a meter for custom metrics"""
    return metrics.get_meter(name)


def get_logger(name: str):
    """Get a logger that emits to OpenTelemetry"""
    return logging.getLogger(name)


setup_opentelemetry(app)
tracer = trace.get_tracer(__name__)
logger = get_logger(__name__)

# setup the loggers/tracers before importing handler to ensure any logging in handler uses the configured logger
from function import handler  # noqa: E402


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

        self.log = ContextLogger(self)

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
            self.log.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.log.error(error_msg, error_type=type(e).__name__)
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
            self.log.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.log.error(error_msg)
            return False, error_msg


class ContextLogger:
    def __init__(self, context: Context):
        self.context = context

    def __call__(self, level: int, message: str, event_type: str = "operation", **attributes):
        self.log(level, message, event_type, **attributes)

    def log(self, level: int, message: str, event_type: str = "operation", **attributes):
        """
        Log with automatic context enrichment and trace correlation.

        Args:
            level: logging level (logging.INFO, logging.ERROR, etc.)
            message: Log message
            event_type: Type of event (operation, admin, audit, error)
            **attributes: Additional structured attributes
        """
        span = trace.get_current_span()
        span_context = span.get_span_context()

        extra = {
            "service": SERVICE_NAME,
            "event_type": event_type,
            "trace_id": format(span_context.trace_id, "032x") if span_context.is_valid else None,
            "span_id": format(span_context.span_id, "016x") if span_context.is_valid else None,
            "scan_id": self.context.scan_id,
            "scan_execution_id": self.context.scan_execution_id,
            "sync_id": self.context.sync_id,
            "sync_execution_id": self.context.sync_execution_id,
            "function_type": self.context.function_type,
            **attributes,
        }

        extra = {k: v for k, v in extra.items() if v is not None}

        logger.log(level, message, extra=extra)

    def info(self, message: str, **attributes):
        self.log(logging.INFO, message, **attributes)

    def error(self, message: str, **attributes):
        self.log(logging.ERROR, message, event_type="error", **attributes)

    def warning(self, message: str, **attributes):
        self.log(logging.WARNING, message, **attributes)

    def debug(self, message: str, **attributes):
        self.log(logging.DEBUG, message, **attributes)


def get_secrets(context: Context, local_run: bool = False) -> dict[str, str]:
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
                    context.log.info("Skipping secret file with unexpected format", filename=filename)
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
                    context.log.info(
                        "Loaded secret",
                        secret_name=camel_key,
                    )
            except Exception as e:
                context.log.error(
                    "Error reading secret file",
                    filename=filename,
                    error=str(e),
                    error_type=type(e).__name__,
                )

    except Exception as e:
        context.log.error("Error reading secrets directory", error=str(e), error_type=type(e).__name__)

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
    with tracer.start_as_current_span("process_request") as span:
        event = Event()
        context = Context()

        context.log.info(
            "Received request",
            http_method=event.method,
            http_path=event.path,
            http_query=dict(event.query),
        )

        try:
            local_run = context.run_local == "true"

            # Load secrets from OpenFaaS secret files
            context.secrets = get_secrets(context, local_run)

            request_data = json.loads(event.body)
            context.scan_execution_id = request_data.get("scanExecutionId")
            context.sync_execution_id = request_data.get("syncExecutionId")

            if not context.secrets:
                context.log.warning("No secrets loaded from secret files")
            else:
                context.log.info(
                    "Loaded secrets from secret files",
                    secret_count=len(context.secrets),
                )

            started_at = datetime.now(UTC).isoformat()

            if context.function_type == "access-scan" or context.function_type == "sync":
                context.update_execution(status="running")
                context.log.info("Started operation", function_type=context.function_type)

            with tracer.start_as_current_span("handle_request"):
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
                    context.log.info(
                        f"Completed {context.function_type} operation successfully",
                        function_type=context.function_type,
                        status="completed",
                    )
                else:
                    context.update_execution(status="failed", completed_at=completed_at)
                    context.log.error(
                        f"Failed {context.function_type} operation",
                        function_type=context.function_type,
                        status="failed",
                        status_code=response_data["statusCode"],
                    )

            with tracer.start_as_current_span("format_response"):
                resp = format_response(response_data)

            status_code = 200
            if isinstance(resp, tuple) and len(resp) >= 2:
                status_code = resp[1]
            span.set_attribute("http.status_code", status_code)
            span.set_status(StatusCode.OK)
            context.log.info("Request completed", http_status_code=status_code)

            return resp
        except Exception as e:
            span.set_attribute("http.status_code", 500)
            span.record_exception(e)
            span.set_status(StatusCode.ERROR)
            context.log.error(
                "Request failed",
                error_type=type(e).__name__,
                error_message=str(e),
            )
            raise


if __name__ == "__main__":
    if os.getenv("DEBUG_MODE", "false").lower() == "true":
        try:
            import debugpy  # noqa: T100

            debugpy.listen((os.getenv("DEBUG_HOST", "0.0.0.0"), int(os.getenv("DEBUG_PORT", 5678))))  # noqa: T100
            debugpy.wait_for_client()  # noqa: T100
        except ImportError:
            app.logger.error("debugpy module not found, continuing without debugger")
        except Exception as e:
            app.logger.error(
                f"Connection to debugger failed: {str(e)}. Ensure your debugger is configured correctly or set DEBUG_MODE to false"
            )

        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=False)
    else:
        serve(app, host="0.0.0.0", port=5000)
