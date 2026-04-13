"""
Unit tests for BatchManager flush-threshold behaviour.

Covers:
- Default threshold is 5 MB
- Threshold is configurable via BATCH_FLUSH_THRESHOLD_BYTES env var
- Flush is triggered when accumulated size would exceed the threshold
- No flush when accumulated size stays within the threshold
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Environment & module stubs required to import index.py in a test context
# ---------------------------------------------------------------------------
# Disable OpenTelemetry initialisation (avoids heavyweight SDK imports)
os.environ.setdefault("OTEL_ENABLED", "false")

# Add parent directory to path for imports (mirrors existing test convention)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Stub modules that are unavailable in the test environment
_stub_modules = [
    "opentelemetry",
    "opentelemetry.context",
    "opentelemetry.metrics",
    "opentelemetry.trace",
    "opentelemetry.trace.status",
    "opentelemetry._logs",
    "opentelemetry.sdk",
    "opentelemetry.sdk._logs",
    "opentelemetry.sdk._logs.export",
    "opentelemetry.sdk.metrics",
    "opentelemetry.sdk.metrics.export",
    "opentelemetry.sdk.resources",
    "opentelemetry.sdk.trace",
    "opentelemetry.sdk.trace.export",
    "opentelemetry.exporter",
    "opentelemetry.exporter.otlp",
    "opentelemetry.exporter.otlp.proto",
    "opentelemetry.exporter.otlp.proto.http",
    "opentelemetry.exporter.otlp.proto.http._log_exporter",
    "opentelemetry.exporter.otlp.proto.http.metric_exporter",
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.instrumentation",
    "opentelemetry.instrumentation.flask",
    "opentelemetry.instrumentation.requests",
    "waitress",
    "function",
    "function.handler",
]
for _mod in _stub_modules:
    sys.modules.setdefault(_mod, MagicMock())

from index import BatchManager, DEFAULT_BATCH_FLUSH_THRESHOLD_BYTES  # noqa: E402


@pytest.fixture
def mock_context():
    """Create a minimal mock Context for BatchManager."""
    ctx = MagicMock()
    ctx.scan_id = "scan-1"
    ctx.scan_execution_id = "exec-1"
    ctx.log = MagicMock()
    ctx.get_caller_headers.return_value = {}
    return ctx


class TestBatchManagerFlushThreshold:
    """Validate that the flush threshold is respected."""

    def test_default_threshold_is_5mb(self, mock_context):
        """BatchManager should default to 5 MB flush threshold."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove the env var if it happens to be set
            os.environ.pop("BATCH_FLUSH_THRESHOLD_BYTES", None)
            bm = BatchManager(mock_context, "objects")
        assert bm.flush_threshold == 5_000_000
        assert DEFAULT_BATCH_FLUSH_THRESHOLD_BYTES == 5_000_000

    def test_threshold_configurable_via_env(self, mock_context):
        """BATCH_FLUSH_THRESHOLD_BYTES env var overrides the default."""
        with patch.dict(os.environ, {"BATCH_FLUSH_THRESHOLD_BYTES": "2000000"}):
            bm = BatchManager(mock_context, "objects")
            assert bm.flush_threshold == 2_000_000

    def test_flush_triggered_when_threshold_exceeded(self, mock_context):
        """_send should be called when adding an object would exceed the threshold."""
        # Use a threshold that allows the first small object but triggers on the second.
        # A small object serialised + scan metadata is roughly 105 bytes, so a
        # threshold of 150 lets the first object through but triggers on the second.
        with patch.dict(os.environ, {"BATCH_FLUSH_THRESHOLD_BYTES": "150"}):
            bm = BatchManager(mock_context, "objects")

        with patch.object(bm, "_send") as mock_send:
            small_obj = {"k": "v"}
            bm.add_object(small_obj)
            # First object fits within 150 bytes — no flush yet
            mock_send.assert_not_called()

            # Second object should push accumulated size past 150 bytes
            bm.add_object(small_obj)
            mock_send.assert_called_once()

    def test_no_flush_when_within_threshold(self, mock_context):
        """No flush should occur when the batch stays under the threshold."""
        # Use a large threshold
        with patch.dict(os.environ, {"BATCH_FLUSH_THRESHOLD_BYTES": "10000000"}):
            bm = BatchManager(mock_context, "objects")

        with patch.object(bm, "_send") as mock_send:
            # Add a small object — should not trigger flush
            bm.add_object({"k": "v"})
            mock_send.assert_not_called()
