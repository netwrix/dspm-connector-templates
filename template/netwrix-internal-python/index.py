#!/usr/bin/env python
import logging
import os
import signal
from collections.abc import Callable
from logging.config import dictConfig
from typing import Final

from flask import Flask, jsonify, request
from opentelemetry import metrics, trace
from opentelemetry.propagate import extract
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

SERVICE_NAME: Final = os.getenv("SERVICE_NAME", __name__)
app = Flask(SERVICE_NAME)


def setup_opentelemetry(app: object | None = None) -> Callable[[], None]:
    """
    Initialize OpenTelemetry instrumentation for traces, metrics, and logs.

    Returns:
        bool: True if setup succeeded, False otherwise
    """

    def noop() -> None:
        return

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
logger = get_logger(SERVICE_NAME)
tracer = get_tracer(SERVICE_NAME)
meter = get_meter(SERVICE_NAME)

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
    def __init__(self, caller_attributes: dict):
        self.user_id = None
        self.tracer = tracer
        self.meter = meter
        self.log = ContextLogger(self)
        self.caller_attributes = caller_attributes


class ContextLogger:
    def __init__(self, context: Context):
        self.hostname = os.getenv("HOSTNAME", "localhost")
        self.service_name = SERVICE_NAME

        self.context = context
        self._logger = get_logger(self.service_name)

    def __call__(self, level: int, message: str, event_type: str = "operation", **attributes):
        self.log(level, message, event_type=event_type, **attributes)

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
            "user_id": self.context.user_id,
            **self.context.caller_attributes,
            **attributes,
        }

        extra = {k: v for k, v in extra.items() if v is not None}

        self._logger.log(level, message, stacklevel=3, extra=extra)

    def info(self, message: str, **attributes):
        self.log(logging.INFO, message, **attributes)

    def error(self, message: str, **attributes):
        self.log(logging.ERROR, message, event_type="error", **attributes)

    def warning(self, message: str, **attributes):
        self.log(logging.WARNING, message, **attributes)

    def debug(self, message: str, **attributes):
        self.log(logging.DEBUG, message, **attributes)


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

@app.before_request
def extract_trace_context():
    headers = dict(request.headers)
    ctx = extract(headers)
    trace.set_span_in_context(ctx)


@app.route("/", defaults={"path": ""}, methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "PUT", "POST", "PATCH", "DELETE"])
def call_handler(path):
    event = Event()

    caller_attributes = {
        "scan_id": event.headers.get("Scan-Id"),
        "scan_execution_id": event.headers.get("Scan-Execution-Id"),
        "sync_id": event.headers.get("Sync-Id"),
        "sync_execution_id": event.headers.get("Sync-Execution-Id"),
    }
    context = Context(caller_attributes)

    context.log.info(
        "Received request",
        http_method=event.method,
        http_path=event.path,
        http_query=dict(event.query),
    )

    try:
        response_data = handler.handle(event, context)
        resp = format_response(response_data)

        status_code = resp[1] if isinstance(resp, tuple) else 200
        context.log.info("Request completed", http_status_code=status_code)

        return resp
    except Exception as e:
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

        app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False)
    else:
        serve(app, host="0.0.0.0", port=5000)
