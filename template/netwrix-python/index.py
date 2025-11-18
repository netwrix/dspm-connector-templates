#!/usr/bin/env python
from __future__ import annotations

import base64
import json
import logging
import os
import signal
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from logging.config import dictConfig
from typing import Final

import orjson
import requests
from flask import Flask, jsonify, request
from opentelemetry import context, metrics, trace
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
SERVICE_NAME: Final = f"{SOURCE_TYPE}-{FUNCTION_TYPE}"
app = Flask(SERVICE_NAME)


def setup_opentelemetry(app: object | None = None) -> Callable[[], None]:
    """
    Initialize OpenTelemetry instrumentation for traces, metrics, and logs.

    Returns:
        bool: True if setup succeeded, False otherwise
    """

    def noop() -> None:
        return None

    if os.getenv("OTEL_ENABLED", "true").lower() != "true":
        logging.info("OpenTelemetry disabled via OTEL_ENABLED environment variable")
        return noop

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
                "service.namespace": "dspm-connectors",
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

        def flush_opentelemetry():
            trace_provider.force_flush()
            metric_provider.force_flush()
            logger_provider.force_flush()

        return flush_opentelemetry

    except Exception:
        logging.exception("Failed to initialize OpenTelemetry")
        return noop


def get_tracer(name: str):
    """Get a tracer for manual instrumentation"""
    return trace.get_tracer(name)


def get_meter(name: str):
    """Get a meter for custom metrics"""
    return metrics.get_meter(name)


def get_logger(name: str):
    """Get a logger that emits to OpenTelemetry"""
    return logging.getLogger(name)


flush_opentelemetry = setup_opentelemetry(app)
tracer = get_tracer(SERVICE_NAME)
logger = get_logger(SERVICE_NAME)

# setup the loggers/tracers before importing handler to ensure any logging in handler uses the configured logger
from function import handler  # noqa: E402


# BatchManager is used to manage the batching of objects for a specific table. It will
# automatically flush the batch when the size of the batch exceeds 1MB.
# It will also update the execution status when the batch is flushed.
# This class is thread-safe and can be used by multiple threads to add objects to the batch.
class BatchManager:
    def __init__(self, context: Context, table_name: str) -> None:
        self.context = context
        self.table_name = table_name
        self.size = 0
        self.rows = b"["  # bytes instead of array for efficient size checks
        self.increment_completed_objects = 0
        self.lock = threading.Lock()

    def add_object(self, obj: object, update_status: bool = True) -> None:
        if obj is not None:
            with self.lock:
                # Add appropriate IDs and timestamp based on operation type (scan vs sync)
                current_time = datetime.now(UTC).isoformat()
                object_data = orjson.dumps(obj)[1:]  # Remove the first brace

                # Check if this is a sync operation
                is_sync_operation = self.context.function_type == "sync"

                if is_sync_operation:
                    # For sync operations - use ClickHouse DateTime format
                    enhanced_object = (
                        b"{"
                        + b'"sync_id":"'
                        + self.context.sync_id.encode("utf-8")
                        + b'",'
                        + b'"sync_execution_id":"'
                        + self.context.sync_execution_id.encode("utf-8")
                        + b'",'
                        + b'"synced_at":"'
                        + current_time.encode("utf-8")
                        + b'",'
                        + object_data  # The last brace is already included in the object_data
                    )
                else:
                    # For scan operations
                    enhanced_object = (
                        b"{"
                        + b'"scan_id":"'
                        + self.context.scan_id.encode("utf-8")
                        + b'",'
                        + b'"scan_execution_id":"'
                        + self.context.scan_execution_id.encode("utf-8")
                        + b'",'
                        + b'"scanned_at":"'
                        + current_time.encode("utf-8")
                        + b'",'
                        + object_data  # The last brace is already included in the object_data
                    )
                size = len(enhanced_object)

                # Set the max size to 500 KB to accommodate for the
                # overhead of the additional fields in the request. This is a good
                # compromise between performance and memory usage and keeps us
                # below the NATS payload limit.
                if size + self.size > 500000:
                    self._flush_internal()

                self.rows += enhanced_object + b","
                self.size += size
                if update_status:
                    self.increment_completed_objects += 1

    def _flush_internal(self) -> tuple[bool, str | None] | None:
        """Internal flush method - assumes lock is already held"""
        success, error = True, None
        local_run = self.context.run_local == "true"

        if len(self.rows) == 1:
            return success, error

        try:
            self.rows = self.rows[:-1] + b"]"  # Remove the last comma and add a closing bracket
            payload = (
                b"{"
                + b'"sourceType":"'
                + os.getenv("SOURCE_TYPE", "").encode("utf-8")
                + b'",'
                + b'"version":"'
                + os.getenv("SOURCE_VERSION", "").encode("utf-8")
                + b'",'
                + b'"table":"'
                + self.table_name.encode("utf-8")
                + b'",'
                + b'"data":'
                + self.rows
                + b"}"
            )

            # Build headers with caller context information
            headers = {"Content-Type": "application/json"}
            headers.update(self.context.get_caller_headers())

            if local_run:
                ## call to local docker container function
                response = requests.post(
                    f"http://{os.getenv('SAVE_DATA_FUNCTION', 'data-ingestion')}:8080",
                    data=payload,
                    headers=headers,
                    timeout=30,
                )
            else:
                response = requests.post(
                    f"{os.getenv('OPENFAAS_GATEWAY')}/async-function/{os.getenv('SAVE_DATA_FUNCTION')}",
                    data=payload,
                    headers=headers,
                    timeout=30,
                )

            if response.status_code in (202, 200):
                if self.increment_completed_objects > 0:
                    self.context.update_execution(
                        increment_completed_objects=self.increment_completed_objects,
                    )
            else:
                error_msg = f"Status {response.status_code}: {response.text}"
                self.context.log.error(error_msg)
                success = False
                error = error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.context.log.error(error_msg, error_type=type(e).__name__)
            success = False
            error = error_msg

        self.size = 0
        self.increment_completed_objects = 0
        self.rows = b"["  # Reset the rows to a new array

        return success, error

    def flush(self) -> tuple[bool, str | None] | None:
        """Public flush method - acquires lock before flushing"""
        with self.lock:
            return self._flush_internal()


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
        self.tables: dict[str, BatchManager] = {}

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

    def flush_tables(self):
        for table in self.tables:
            self.tables[table].flush()

    def get_caller_headers(self) -> dict[str, str]:
        """
        Build headers dict with caller context information to pass to common functions.
        Only includes headers that have non-None values.
        """
        headers = {}
        if self.scan_id:
            headers["Scan-Id"] = self.scan_id
        if self.scan_execution_id:
            headers["Scan-Execution-Id"] = self.scan_execution_id
        if self.sync_id:
            headers["Sync-Id"] = self.sync_id
        if self.sync_execution_id:
            headers["Sync-Execution-Id"] = self.sync_execution_id
        return headers

    def create_thread(self, target, *args, **kwargs):
        """
        Create a thread that automatically inherits the current OpenTelemetry context.

        Usage:
            def my_worker(arg1, arg2):
                context.log.info("Working with trace context!")

            thread = self.create_thread(target=my_worker, args=(val1, val2), name="Worker-1")
            thread.start()
        """
        # Capture the current context
        current_context = context.get_current()

        # Wrap the target function to attach context
        original_target = target

        def wrapped_target(*target_args, **target_kwargs):
            token = context.attach(current_context)
            try:
                return original_target(*target_args, **target_kwargs)
            finally:
                context.detach(token)

        # Create thread with wrapped target
        return threading.Thread(*args, target=wrapped_target, **kwargs)

    # Add an object to the appropriate table batch manager
    def save_object(self, table: str, obj: object, update_status: bool = True):
        if table not in self.tables:
            self.tables[table] = BatchManager(self, table)

        self.tables[table].add_object(obj, update_status)

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

            # Build headers with caller context information
            headers = {"Content-Type": "application/json"}
            headers.update(self.get_caller_headers())

            if local_run:
                response = requests.post(
                    f"http://{os.getenv('SAVE_DATA_FUNCTION', 'data-ingestion')}:8080",
                    json=payload,
                    headers=headers,
                    timeout=30,
                )
            else:
                response = requests.post(
                    f"{os.getenv('OPENFAAS_GATEWAY')}/async-function/{os.getenv('APP_UPDATE_EXECUTION_FUNCTION')}",
                    json=payload,
                    headers=headers,
                    timeout=30,
                )

            if response.status_code in (202, 200):
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
        self.service_name = SERVICE_NAME
        self._logger = get_logger(self.service_name)

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
            "service": self.service_name,
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

        logger.log(level, message, stacklevel=3, extra=extra)

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

    secret_mappings = os.getenv("SECRET_MAPPINGS", "").split(",")
    secret_mappings_dict = {mapping.split(":")[0]: mapping.split(":")[1] for mapping in secret_mappings}
    for key, path in secret_mappings_dict.items():
        try:
            with open(os.path.join(secrets_dir, path)) as f:
                secrets_dict[key] = f.read().strip()
                context.log.info(
                    "Loaded secret",
                    secret_name=key,
                )
        except Exception as e:
            context.log.error(
                "Error reading secret file",
                filename=path,
                error=str(e),
                error_type=type(e).__name__,
            )

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

            # Flush remaining rows in all tables
            context.flush_tables()

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


def handle_shutdown(signum, frame):
    flush_opentelemetry()


signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

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
