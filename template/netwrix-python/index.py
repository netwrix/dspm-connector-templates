#!/usr/bin/env python
from __future__ import annotations

import sys

# When index.py runs as __main__, register it under the name "index" so that
# `from index import ...` in other modules resolves to the
# already-loaded module instead of re-executing the file.
sys.modules.setdefault("index", sys.modules[__name__])

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
PROCESS_KEY: Final = os.getenv("POST_PROCESSING_KEY")
SERVICE_NAME: Final = f"{SOURCE_TYPE}-{PROCESS_KEY}" if PROCESS_KEY else f"{SOURCE_TYPE}-{FUNCTION_TYPE}"

# Common functions base URL - defaults to access-analyzer namespace K8s services
# For local development, set to appropriate docker-compose service names
COMMON_FUNCTIONS_NAMESPACE: Final = os.getenv("COMMON_FUNCTIONS_NAMESPACE", "access-analyzer")

app = Flask(SERVICE_NAME)


def get_service_url(service_name: str, port: int = 80, use_async: bool = False) -> str:
    """
    Get the URL for a common function service.

    Supports three deployment modes:
    1. Local development (RUN_LOCAL=true): uses simple service name with port 8080
    2. Kubernetes with USE_OPENFAAS_GATEWAY=false (default): uses FQDN
       Format: http://<service-name>.<namespace>.svc.cluster.local:<port>
    3. OpenFaaS (USE_OPENFAAS_GATEWAY=true): uses OpenFaaS gateway
       Format: http://<gateway>/function/<service-name> or
               http://<gateway>/async-function/<service-name> (if use_async=True)

    Args:
        service_name: Name of the service to call
        port: Port number for Kubernetes FQDN (default: 80)
        use_async: If True and using OpenFaaS, uses async-function endpoint instead of function
    """
    local_run = os.getenv("RUN_LOCAL", "false") == "true"
    use_openfaas = os.getenv("USE_OPENFAAS_GATEWAY", "false") == "true"

    if local_run:
        # Local docker-compose: service names are directly resolvable
        return f"http://{service_name}:8080"

    if use_openfaas:
        # OpenFaaS: use gateway URL with async-function for fire-and-forget calls
        openfaas_gateway = os.getenv("OPENFAAS_GATEWAY", "http://gateway.openfaas:8080")
        endpoint = "async-function" if use_async else "function"
        return f"{openfaas_gateway}/{endpoint}/{service_name}"

    # Kubernetes: use fully qualified DNS name
    return f"http://{service_name}.{COMMON_FUNCTIONS_NAMESPACE}.svc.cluster.local:{port}"


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

        logging.info("OpenTelemetry initialized successfully")

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


# Default flush threshold in bytes (5 MB). Override via BATCH_FLUSH_THRESHOLD_BYTES env var.
DEFAULT_BATCH_FLUSH_THRESHOLD_BYTES: Final[int] = 5_000_000


# BatchManager is used to manage the batching of objects for a specific table. It will
# automatically flush the batch when the size exceeds the configured threshold.
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
        self.flush_threshold = int(
            os.getenv("BATCH_FLUSH_THRESHOLD_BYTES", str(DEFAULT_BATCH_FLUSH_THRESHOLD_BYTES))
        )

    def add_object(self, obj: object, update_status: bool = True) -> None:
        if obj is None:
            return

        # Build the enhanced object before acquiring the lock — each thread
        # works on its own local variables, so this is safe to do in parallel.
        current_time = datetime.now(UTC).isoformat()
        object_data = orjson.dumps(obj)[1:]  # Remove the first brace

        # For scan operations - ensure scan_id and scan_execution_id are set
        scan_id = self.context.scan_id or ""
        scan_execution_id = self.context.scan_execution_id or ""

        enhanced_object = (
            b"{"
            + b'"scan_id":"'
            + scan_id.encode("utf-8")
            + b'",'
            + b'"scan_execution_id":"'
            + scan_execution_id.encode("utf-8")
            + b'",'
            + b'"scanned_at":"'
            + current_time.encode("utf-8")
            + b'",'
            + object_data  # The last brace is already included in the object_data
        )
        size = len(enhanced_object)

        rows_to_flush = None
        count_to_flush = 0

        # Flush when adding this object would exceed the configured
        # threshold. The default (5 MB) balances throughput against
        # memory usage and stays within typical message-broker limits.
        with self.lock:
            if size + self.size > self.flush_threshold:
                # Swap out the full buffer while holding the lock (nanoseconds),
                # then send it outside the lock so other threads are not blocked
                # during the HTTP call.
                rows_to_flush = self.rows
                count_to_flush = self.increment_completed_objects
                self.rows = b"["
                self.size = 0
                self.increment_completed_objects = 0

            self.rows += enhanced_object + b","
            self.size += size
            if update_status:
                self.increment_completed_objects += 1

        if rows_to_flush is not None:
            self._send(rows_to_flush, count_to_flush)

    def _send(self, rows: bytes, count: int) -> None:
        """Send a captured buffer snapshot. Must be called outside the lock."""
        if len(rows) == 1:  # just b"[" — nothing to send
            return

        try:
            payload = (
                b"{"
                + b'"sourceType":"'
                + os.getenv("SOURCE_TYPE", "").encode("utf-8")
                + b'",'
                + b'"table":"'
                + self.table_name.encode("utf-8")
                + b'",'
                + b'"data":'
                + rows[:-1]  # strip trailing comma
                + b"]}"
            )

            # Build headers with caller context information
            headers = {"Content-Type": "application/json", **self.context.get_caller_headers()}

            # Get service URL for data-ingestion (use async for OpenFaaS fire-and-forget)
            service_name = os.getenv("SAVE_DATA_FUNCTION", "data-ingestion")
            url = get_service_url(service_name, use_async=True)

            response = requests.post(
                url,
                data=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code in (202, 200):
                if count > 0:
                    self.context.update_execution(
                        increment_completed_objects=count,
                    )
            else:
                error_msg = f"Status {response.status_code}: {response.text}"
                self.context.log.error(error_msg)
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.context.log.error(error_msg, error_type=type(e).__name__)

    def flush(self) -> None:
        """Flush any remaining buffered rows. Called once at end of scan/sync."""
        with self.lock:
            rows, count = self.rows, self.increment_completed_objects
            self.rows = b"["
            self.size = 0
            self.increment_completed_objects = 0
        # Send outside the lock — same pattern as add_object
        self._send(rows, count)


class Event:
    def __init__(self, execution_mode: str = "http"):
        if execution_mode == "http":
            # HTTP mode: read from Flask request
            self.body = request.get_data()
            self.headers = request.headers
            self.method = request.method
            self.query = request.args
            self.path = request.path
        else:
            # Job mode: read from REQUEST_DATA environment variable (equivalent to HTTP POST body)
            request_data = os.getenv("REQUEST_DATA", "{}")
            self.body = request_data.encode()
            self.headers = {}
            self.method = "POST"
            self.query = {}
            self.path = "/"


class Context:
    def __init__(self):
        self.secrets: dict[str, str] | None = None
        self.scan_id: str | None = os.getenv("SCAN_ID")
        self.scan_execution_id: str | None = None
        self.parent_execution_id: str | None = None
        self.run_local: str = os.getenv("RUN_LOCAL", "false")
        self.function_type: str | None = os.getenv("FUNCTION_TYPE")
        self.tables: dict[str, BatchManager] = {}

        self.log = ContextLogger(self)

    @property
    def source_type(self) -> str:
        return SOURCE_TYPE

    def test_connection_success_response(self):
        return {"statusCode": 200, "body": {}}

    def access_scan_success_response(self):
        return {"statusCode": 200, "body": {}}

    def get_object_success_response(self, data):
        encoded_data = base64.b64encode(data).decode("utf-8")

        return {"statusCode": 200, "body": {"data": encoded_data}}

    def error_response(self, client_error, error_msg):
        status_code = 400 if client_error else 500
        self.log.error(error_msg, status_code=status_code)

        return {"statusCode": status_code, "body": {"error": error_msg}}

    def flush_tables(self):
        for table in self.tables:
            self.tables[table].flush()

    def get_caller_headers(self) -> dict[str, str]:
        """
        Build headers dict with caller context information to pass to common functions.
        Only includes headers that have non-None values.
        """
        return {"Scan-Id": self.scan_id or "", "Scan-Execution-Id": self.scan_execution_id or ""}

    def get_connector_state(self) -> dict:
        """
        Retrieve connector state from the connector-state function for the current scan_id.

        Returns:
            dict: Dictionary containing the connector state key-value pairs

        Raises:
            ValueError: If scan_id is not set
            Exception: If the request fails
        """
        if not self.scan_id:
            raise ValueError("scan_id must be set to retrieve connector state")

        try:
            # Build headers with caller context information
            headers = {"Content-Type": "application/json", **self.get_caller_headers()}

            # Get service URL for connector-state
            service_name = os.getenv("CONNECTOR_STATE_FUNCTION", "connector-state")
            url = get_service_url(service_name)

            response = requests.get(
                url,
                params={"scanId": self.scan_id},
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    self.log.info("Retrieved connector state successfully", key_count=len(result.get("data", {})))
                    return result.get("data", {})
                error_msg = f"Failed to retrieve connector state: {result.get('error', 'Unknown error')}"
                raise Exception(error_msg)

            error_msg = f"Status {response.status_code}: {response.text}"
            raise Exception(error_msg)
        except Exception:
            raise

    def delete_connector_state(self, names: list[str] | None = None) -> tuple[bool, str | None]:
        """
        Delete connector state from the connector-state function for the current scan_id.

        Args:
            names: Optional list of item names to delete. If None, deletes all data for the scan_id.

        Returns:
            tuple: (success: bool, error_message: str | None)

        Raises:
            ValueError: If scan_id is not set
        """
        if not self.scan_id:
            raise ValueError("scan_id must be set to delete connector state")

        try:
            # Build params with scanId and optional name parameters
            params: dict[str, str | list[str]] = {"scanId": self.scan_id}
            if names:
                # Add multiple name parameters to the query string
                params["name"] = names

            # Build headers with caller context information
            headers = {"Content-Type": "application/json", **self.get_caller_headers()}

            # Get service URL for connector-state
            service_name = os.getenv("CONNECTOR_STATE_FUNCTION", "connector-state")
            url = get_service_url(service_name)

            response = requests.delete(
                url,
                params=params,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    log_attrs = {}
                    if names:
                        log_attrs["deleted_names"] = names
                        log_attrs["deleted_count"] = len(names)
                    self.log.info("Deleted connector state successfully", **log_attrs)
                    return True, None
                error_msg = f"Failed to delete connector state: {result.get('error', 'Unknown error')}"
                return False, error_msg

            error_msg = f"Status {response.status_code}: {response.text}"
            return False, error_msg
        except Exception as e:
            error_msg = f"Error deleting connector state: {str(e)}"
            return False, error_msg

    def set_connector_state(self, data: dict) -> tuple[bool, str | None]:
        """
        Save connector state to the connector-state function for the current scan_id.

        Args:
            data: Dictionary of key-value pairs to save

        Returns:
            tuple: (success: bool, error_message: str | None)

        Raises:
            ValueError: If scan_id is not set or data is not a dictionary
        """
        if not self.scan_id:
            raise ValueError("scan_id must be set to save connector state")

        if not isinstance(data, dict):
            raise ValueError("data must be a dictionary")

        try:
            payload = {"scanId": self.scan_id, "data": data}

            # Build headers with caller context information
            headers = {"Content-Type": "application/json", **self.get_caller_headers()}

            # Get service URL for connector-state
            service_name = os.getenv("CONNECTOR_STATE_FUNCTION", "connector-state")
            url = get_service_url(service_name)

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    self.log.info("Saved connector state successfully", key_count=len(data))
                    return True, None
                error_msg = f"Failed to save connector state: {result.get('error', 'Unknown error')}"
                return False, error_msg

            error_msg = f"Status {response.status_code}: {response.text}"
            return False, error_msg
        except Exception as e:
            error_msg = f"Error saving connector state: {str(e)}"
            return False, error_msg

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

    def run_process_async(self, process_key: str) -> None:
        """
        Trigger an additional process asynchronously as a new child of the parent execution.

        This allows a handler to kick off other named processes defined in the connector's
        config.json `additionalProcesses` array. The new child execution runs under the same
        parent, so it participates in the same lifecycle (its completion is tracked and the
        parent only completes when all children are done).

        Args:
            process_key: The key of the additional process to trigger (must match the handler
                         directory name and the `key` field in `additionalProcesses`).

        Raises:
            ValueError: If parent_execution_id is not set on the context.
            requests.HTTPError: If the core-api call fails.
        """
        if not self.parent_execution_id:
            raise ValueError("parent_execution_id must be set to call run_process_async")

        base_url = os.getenv("CORE_API_INTERNAL_URL", "http://core-api:3000")
        url = f"{base_url}/api/v1/scan-executions/{self.parent_execution_id}/run-process"

        headers = {"Content-Type": "application/json"}
        api_key = os.getenv("CONNECTOR_API_KEY", "")
        if api_key:
            headers["X-Api-Key"] = api_key

        response = requests.post(
            url,
            json={"processKey": process_key},
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()

        result = response.json()
        self.log.info("Triggered additional process", process_key=process_key, execution_id=result.get("executionId"))

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
        try:
            # Build payload with only provided arguments
            payload = {"executionId": self.scan_execution_id}

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
            headers = {"Content-Type": "application/json", **self.get_caller_headers()}

            # Log the update request details
            self.log.debug(f"Calling update_execution: id={self.scan_execution_id}, status={status}, payload={payload}")

            # Get service URL for app-update-execution
            service_name = os.getenv("APP_UPDATE_EXECUTION_FUNCTION", "app-update-execution")
            url = get_service_url(service_name)
            self.log.debug(f"Sending update_execution to URL: {url}")

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

            if response.status_code in (202, 200):
                self.log.debug(
                    f"update_execution succeeded: status_code={response.status_code}, response={response.text[:200] if response.text else ''}"
                )
                return True, None
            error_msg = f"Status {response.status_code}: {response.text}"
            self.log.error(f"update_execution failed: {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.log.error("update_execution exception", error_msg=error_msg, error_type=type(e).__name__)
            return False, error_msg

    def get_prior_execution(self, scan_execution_id: str) -> dict | None:
        """
        Query Postgres scan_executions table for prior execution with same scan_execution_id.

        Used to detect if a scan is resuming from a paused state.

        Args:
            scan_execution_id: The execution ID to query

        Returns:
            dict with 'status' field if found, None if not found or on error
        """
        local_run = self.run_local == "true"

        try:
            # Query Postgres for scan execution status via app-data-query function
            query = (
                f"SELECT id, status, completed_objects FROM scan_executions WHERE id = '{scan_execution_id}' LIMIT 1"
            )
            payload = {"query": query}

            # Build headers with caller context information
            headers = {"Content-Type": "application/json", **self.get_caller_headers()}

            if local_run:
                url = f"http://{os.getenv('APP_DATA_QUERY_FUNCTION', 'app-data-query')}:8080"
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=30,
                )
            else:
                url = (
                    f"{os.getenv('OPENFAAS_GATEWAY')}/function/{os.getenv('APP_DATA_QUERY_FUNCTION', 'app-data-query')}"
                )
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=30,
                )

            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    data = result.get("data", [])
                    if data and len(data) > 0:
                        execution_data = data[0]
                        completed_objects = execution_data.get("completed_objects")
                        if completed_objects > 0:
                            self.log.info(
                                "Retrieved prior execution",
                                scan_execution_id=scan_execution_id,
                                completed_objects=completed_objects,
                                status=execution_data.get("status"),
                            )
                            return execution_data
                    self.log.info("No prior execution found", scan_execution_id=scan_execution_id)
                    return None
                self.log.info(
                    "Query failed", scan_execution_id=scan_execution_id, error=result.get("error", "Unknown error")
                )
                return None
            self.log.info(
                "Failed to query prior execution", status_code=response.status_code, response=response.text[:200]
            )
            return None

        except Exception as e:
            self.log.warning("Error querying prior execution", scan_execution_id=scan_execution_id, error=str(e))
            return None


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
    """Read secrets from available mount paths.

    Supports both OpenFaaS (/var/openfaas/secrets/) and connector-api (/var/secrets/) paths.
    Both use the same flat file structure: <base-path>/<secret-name> containing the raw value.
    """
    secrets_dict: dict[str, str] = {}

    # Both paths use flat file structure (not directories)
    connector_api_path = "/var/secrets/"
    openfaas_path = "/var/openfaas/secrets/"

    secret_mappings = os.getenv("SECRET_MAPPINGS", "").split(",")
    secret_mappings_dict = {
        mapping.split(":")[0]: mapping.split(":")[1] for mapping in secret_mappings if ":" in mapping
    }

    for key, secret_name in secret_mappings_dict.items():
        secret_value = None

        # Try connector-api path first: /var/secrets/<secret-name>
        secret_file_path = os.path.join(connector_api_path, secret_name)
        if os.path.isfile(secret_file_path):
            try:
                with open(secret_file_path) as f:
                    secret_value = f.read().strip()
            except Exception as e:
                context.log.error(
                    "Error reading secret file",
                    filename=secret_file_path,
                    error=str(e),
                    error_type=type(e).__name__,
                )

        # Fallback to OpenFaaS path: /var/openfaas/secrets/<secret-name>
        if secret_value is None:
            secret_file_path = os.path.join(openfaas_path, secret_name)
            if os.path.isfile(secret_file_path):
                try:
                    with open(secret_file_path) as f:
                        secret_value = f.read().strip()
                except Exception as e:
                    context.log.error(
                        "Error reading secret file",
                        filename=secret_file_path,
                        error=str(e),
                        error_type=type(e).__name__,
                    )

        if secret_value is not None:
            secrets_dict[key] = secret_value
            context.log.info("Loaded secret", secret_key=key)
        else:
            context.log.warning("Secret not found", secret_key=key, secret_name=secret_name)

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


@app.get("/health")
def health():
    return jsonify(status="ok")


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

            # Load secrets from secret files
            context.secrets = get_secrets(context, local_run)

            request_data = json.loads(event.body)
            context.scan_execution_id = request_data.get("scanExecutionId")
            context.parent_execution_id = request_data.get("parentExecutionId") or None

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
                    # Check if handler already set a specific status (like 'stopped' or 'paused')
                    # If not, default to 'completed'
                    response_status = response_data.get("body", {}).get("status")
                    if response_status == "stopped":
                        # Scan was stopped, make sure execution status is updated
                        context.update_execution(status="stopped", completed_at=completed_at)
                        context.log.info(
                            "Scan was stopped",
                            function_type=context.function_type,
                            status="stopped",
                        )
                    elif response_status == "paused":
                        # Scan was paused, make sure execution status is updated
                        context.update_execution(status="paused")
                        context.log.info(
                            "Scan was paused",
                            function_type=context.function_type,
                            status="paused",
                        )
                    else:
                        # Normal completion - update to completed
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


def get_execution_mode() -> str:
    """Detect execution mode based on environment.

    Returns:
        str: 'job' for Kubernetes job mode, 'http' for HTTP server mode
    """
    # Explicit mode override
    if os.getenv("EXECUTION_MODE") == "job":
        return "job"

    # If REQUEST_DATA is set, assume job mode
    if os.getenv("REQUEST_DATA"):
        return "job"

    # Default to HTTP server mode
    return "http"


def run_as_job():
    """Execute handler once as a Kubernetes job."""
    # Create a root span for the job execution
    with tracer.start_as_current_span("job_execution") as span:
        started_at = datetime.now(UTC).isoformat()

        ctx = Context()
        ctx.secrets = get_secrets(ctx)

        # Parse scan/sync execution ID from environment or REQUEST_DATA
        request_data_str = os.getenv("REQUEST_DATA", "{}")
        try:
            request_data = json.loads(request_data_str)
        except json.JSONDecodeError:
            request_data = {}

        ctx.scan_execution_id = request_data.get("scanExecutionId") or os.getenv("SCAN_EXECUTION_ID")
        ctx.parent_execution_id = request_data.get("parentExecutionId") or None

        ctx.log.info(
            "Starting job execution",
            execution_mode="job",
            function_type=ctx.function_type,
            scan_id=ctx.scan_id,
            scan_execution_id=ctx.scan_execution_id,
        )

        event = Event(execution_mode="job")

        try:
            # Update execution status to running for scan/sync operations
            if ctx.function_type in ("access-scan", "sync"):
                ctx.update_execution(status="running")
                ctx.log.info("Started operation", function_type=ctx.function_type)

            # Run the handler
            with tracer.start_as_current_span("handle_request"):
                response = handler.handle(event, ctx)

            # Flush any remaining batched data
            ctx.flush_tables()

            completed_at = datetime.now(UTC).isoformat()

            # Update execution status based on response
            status_code = response.get("statusCode", 500)
            success = status_code == 200

            if ctx.function_type in ("access-scan", "sync"):
                if success:
                    # Check if handler set a specific status (like 'stopped' or 'paused')
                    response_status = response.get("body", {}).get("status")
                    if response_status == "stopped":
                        ctx.update_execution(status="stopped", completed_at=completed_at)
                        ctx.log.info("Operation was stopped", function_type=ctx.function_type, status="stopped")
                    elif response_status == "paused":
                        ctx.update_execution(status="paused", completed_at=completed_at)
                        ctx.log.info("Operation was paused", function_type=ctx.function_type, status="paused")
                    else:
                        ctx.update_execution(status="completed", completed_at=completed_at)
                        ctx.log.info(
                            f"Completed {ctx.function_type} operation successfully",
                            function_type=ctx.function_type,
                            status="completed",
                        )
                else:
                    ctx.update_execution(status="failed", completed_at=completed_at)
                    ctx.log.error(
                        f"Failed {ctx.function_type} operation",
                        function_type=ctx.function_type,
                        status="failed",
                        status_code=status_code,
                    )

            # Determine final status
            final_status = response.get("body", {}).get("status", "completed") if success else "failed"

            # Output result as JSON to stdout
            result = {
                "success": success,
                "status": final_status,
                "statusCode": status_code,
                "body": response.get("body", {}),
                "startedAt": started_at,
                "completedAt": completed_at,
            }

            # Set span attributes
            span.set_attribute("job.status", final_status)
            span.set_attribute("job.status_code", status_code)
            span.set_status(StatusCode.OK if success else StatusCode.ERROR)

            ctx.log.info("Job execution completed", success=success, status=final_status)

        except Exception as e:
            completed_at = datetime.now(UTC).isoformat()

            # Update execution status to failed for scan/sync operations
            if ctx.function_type in ("access-scan", "sync"):
                ctx.update_execution(status="failed", completed_at=completed_at)

            span.record_exception(e)
            span.set_status(StatusCode.ERROR)

            ctx.log.error(
                "Job execution failed",
                error_type=type(e).__name__,
                error_message=str(e),
            )

            result = {
                "success": False,
                "status": "failed",
                "statusCode": 500,
                "body": {"error": str(e)},
                "startedAt": started_at,
                "completedAt": completed_at,
            }

        # Flush OpenTelemetry before exiting
        flush_opentelemetry()

        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)


def run_as_http_server():
    """Start Flask HTTP server for OpenFaaS mode."""
    port = os.getenv("PORT", 5000)
    serve(app, host="0.0.0.0", port=port)


def main():
    """Main entry point - detect execution mode and run accordingly."""
    execution_mode = get_execution_mode()

    if execution_mode == "job":
        # Job mode: run handler once and exit
        run_as_job()
    else:
        # HTTP mode: start Flask server
        run_as_http_server()


if __name__ == "__main__":
    main()
