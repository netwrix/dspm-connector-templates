"""
Unit tests for redis_signal_handler module using pytest framework
Tests cover:
- Redis connection management
- Control signal reading
- Status updates
- Stream cleanup
- Health checks
- Pause and resume functionality
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Import the module to test
from redis_signal_handler import RedisSignalHandler, ScanControlContext


class TestRedisSignalHandler:
    """Test RedisSignalHandler class"""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client"""
        return MagicMock()

    @pytest.fixture
    def handler(self, mock_redis_client):
        """Create RedisSignalHandler with mocked Redis"""
        with patch("redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler("redis://localhost:6379")
            return handler

    def test_initialization_success(self, mock_redis_client):
        """Test successful Redis connection"""
        mock_redis_client.ping.return_value = True

        with patch("redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler("redis://localhost:6379")

        assert handler.client is not None
        assert handler.redis_url == "redis://localhost:6379"

    def test_initialization_failure(self):
        """Test failed Redis connection"""
        with patch("redis.from_url") as mock_from_url:
            mock_from_url.side_effect = Exception("Connection refused")
            handler = RedisSignalHandler("redis://localhost:6379")

        assert handler.client is None

    def test_check_control_signal_success(self, handler, mock_redis_client):
        """Test successful control signal reading"""
        handler.client = mock_redis_client

        # Mock xread response
        mock_redis_client.xread.return_value = [
            ("scan:control:exec-123", [("1234567890-0", {"action": "STOP", "reason": "user_request"})])
        ]

        signal = handler.check_control_signal("exec-123", "0")

        assert signal is not None
        assert signal["action"] == "STOP"
        assert signal["_id"] == "1234567890-0"

    def test_check_control_signal_no_signal(self, handler, mock_redis_client):
        """Test no control signal available"""
        handler.client = mock_redis_client
        mock_redis_client.xread.return_value = []

        signal = handler.check_control_signal("exec-123", "0")

        assert signal is None

    def test_check_control_signal_timeout(self, handler, mock_redis_client):
        """Test timeout when reading control signal"""
        handler.client = mock_redis_client
        mock_redis_client.xread.side_effect = Exception("Timeout")

        signal = handler.check_control_signal("exec-123", "0")

        assert signal is None

    def test_update_status_success(self, handler, mock_redis_client):
        """Test successful status update"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-2"

        result = handler.update_status(
            "exec-123", "stopping", "Stop signal received", {"partial_data": True, "objects_count": 50}
        )

        assert result == "1234567890-2"
        mock_redis_client.xadd.assert_called_once()

    def test_cleanup_streams_success(self, handler, mock_redis_client):
        """Test successful stream cleanup"""
        handler.client = mock_redis_client
        mock_redis_client.delete.return_value = 2

        result = handler.cleanup_streams("exec-123")

        assert result is True
        mock_redis_client.delete.assert_called_once()

    def test_cleanup_streams_failure(self, handler, mock_redis_client):
        """Test stream cleanup failure"""
        handler.client = mock_redis_client
        mock_redis_client.delete.side_effect = Exception("Redis error")

        result = handler.cleanup_streams("exec-123")

        assert result is False

    def test_health_check_success(self, handler, mock_redis_client):
        """Test successful health check"""
        handler.client = mock_redis_client
        mock_redis_client.ping.return_value = True

        result = handler.health_check()

        assert result is True

    def test_health_check_connection_present(self, handler, mock_redis_client):
        """Test health check with healthy connection"""
        handler.client = mock_redis_client
        mock_redis_client.ping.return_value = True

        result = handler.health_check()

        assert result is True
        mock_redis_client.ping.assert_called()

    def test_close(self, handler, mock_redis_client):
        """Test closing Redis connection"""
        handler.client = mock_redis_client

        handler.close()

        mock_redis_client.close.assert_called_once()
        assert handler.client is None

    def test_close_with_error(self, handler, mock_redis_client):
        """Test closing Redis connection with error"""
        handler.client = mock_redis_client
        mock_redis_client.close.side_effect = Exception("Close error")

        # Should not raise exception
        handler.close()

        assert handler.client is None

    def test_context_manager(self, mock_redis_client):
        """Test using RedisSignalHandler as context manager"""
        with patch("redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            mock_redis_client.ping.return_value = True

            with RedisSignalHandler("redis://localhost:6379") as handler:
                assert handler.client is not None

            mock_redis_client.close.assert_called_once()


class TestScanControlContext:
    """Test ScanControlContext class"""

    @pytest.fixture
    def mock_handler(self):
        """Create a mock RedisSignalHandler"""
        return MagicMock(spec=RedisSignalHandler)

    @pytest.fixture
    def context(self, mock_handler):
        """Create ScanControlContext with mocked handler"""
        return ScanControlContext("exec-123", mock_handler)

    def test_initialization(self, context):
        """Test ScanControlContext initialization"""
        assert context.execution_id == "exec-123"
        assert context.stop_requested is False
        assert context.pause_requested is False
        assert context.last_signal_id == "0"

    def test_check_for_signals_stop(self, context, mock_handler):
        """Test checking for STOP signal"""
        mock_handler.check_control_signal.return_value = {"action": "STOP", "_id": "123-0"}

        result = context.check_for_signals()

        assert result is True
        assert context.stop_requested is True
        assert context.last_signal_id == "123-0"

    def test_check_for_signals_pause(self, context, mock_handler):
        """Test checking for PAUSE signal"""
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "123-0"}

        result = context.check_for_signals()

        # PAUSE signal returns True to indicate signal was received
        assert result is True
        assert context.pause_requested is True

    def test_check_for_signals_resume(self, context, mock_handler):
        """Test checking for RESUME signal"""
        context.pause_requested = True
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "123-0"}

        context.check_for_signals()

        assert context.pause_requested is False

    def test_check_for_signals_none(self, context, mock_handler):
        """Test checking for signals when none available"""
        mock_handler.check_control_signal.return_value = None

        result = context.check_for_signals()

        assert result is False

    def test_should_stop(self, context):
        """Test should_stop method"""
        assert context.should_stop() is False

        context.stop_requested = True
        assert context.should_stop() is True

    def test_should_pause(self, context):
        """Test should_pause method"""
        assert context.should_pause() is False

        context.pause_requested = True
        assert context.should_pause() is True


class TestPauseResumeFeature:
    """Test pause and resume signal handling"""

    @pytest.fixture
    def mock_handler(self):
        """Create a mock RedisSignalHandler"""
        return MagicMock(spec=RedisSignalHandler)

    @pytest.fixture
    def context(self, mock_handler):
        """Create ScanControlContext with mocked handler"""
        return ScanControlContext("exec-123", mock_handler)

    def test_pause_signal_sets_pause_requested(self, context, mock_handler):
        """Test that PAUSE signal sets pause_requested flag"""
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "456-0"}

        result = context.check_for_signals()

        assert context.pause_requested is True
        assert context.stop_requested is False
        # PAUSE signal returns True to indicate signal was received
        assert result is True

    def test_resume_signal_clears_pause_requested(self, context, mock_handler):
        """Test that RESUME signal clears pause_requested flag"""
        context.pause_requested = True
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "789-0"}

        context.check_for_signals()

        assert context.pause_requested is False
        assert context.stop_requested is False

    def test_pause_then_resume_sequence(self, context, mock_handler):
        """Test pause followed by resume signal sequence"""
        # First: pause signal
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "100-0"}
        context.check_for_signals()
        assert context.pause_requested is True

        # Then: resume signal
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "101-0"}
        context.check_for_signals()
        assert context.pause_requested is False

    def test_resume_when_not_paused(self, context, mock_handler):
        """Test RESUME signal when not paused (should still work)"""
        context.pause_requested = False
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "200-0"}

        context.check_for_signals()

        assert context.pause_requested is False

    def test_should_pause_returns_true_when_paused(self, context):
        """Test should_pause method returns True when paused"""
        context.pause_requested = True

        assert context.should_pause() is True

    def test_should_pause_returns_false_when_not_paused(self, context):
        """Test should_pause method returns False when not paused"""
        context.pause_requested = False

        assert context.should_pause() is False

    def test_pause_preserves_last_signal_id(self, context, mock_handler):
        """Test that pause signal updates last_signal_id"""
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "pause-123"}

        context.check_for_signals()

        assert context.last_signal_id == "pause-123"

    def test_multiple_pause_resume_cycles(self, context, mock_handler):
        """Test multiple pause/resume cycles"""
        # Cycle 1: pause
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "300-0"}
        context.check_for_signals()
        assert context.pause_requested is True

        # Cycle 1: resume
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "301-0"}
        context.check_for_signals()
        assert context.pause_requested is False

        # Cycle 2: pause again
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "302-0"}
        context.check_for_signals()
        assert context.pause_requested is True

        # Cycle 2: resume again
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "303-0"}
        context.check_for_signals()
        assert context.pause_requested is False

    def test_stop_signal_overrides_pause(self, context, mock_handler):
        """Test that STOP signal is handled even during pause"""
        context.pause_requested = True
        mock_handler.check_control_signal.return_value = {"action": "STOP", "_id": "400-0"}

        result = context.check_for_signals()

        assert context.stop_requested is True
        assert result is True  # STOP should return True

    def test_pause_signal_maintains_stop_state(self, context, mock_handler):
        """Test that pause signal doesn't affect stop_requested flag"""
        context.stop_requested = True
        mock_handler.check_control_signal.return_value = {"action": "PAUSE", "_id": "500-0"}

        context.check_for_signals()

        assert context.stop_requested is True  # Should remain True

    def test_resume_does_not_set_stop_requested(self, context, mock_handler):
        """Test that RESUME signal doesn't set stop_requested"""
        context.pause_requested = True
        mock_handler.check_control_signal.return_value = {"action": "RESUME", "_id": "600-0"}

        context.check_for_signals()

        assert context.stop_requested is False


class TestPauseResumeWithRedisHandler:
    """Test pause/resume feature with RedisSignalHandler integration"""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client"""
        return MagicMock()

    @pytest.fixture
    def handler(self, mock_redis_client):
        """Create RedisSignalHandler with mocked Redis"""
        with patch("redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler("redis://localhost:6379")
            return handler

    def test_check_control_signal_pause(self, handler, mock_redis_client):
        """Test reading PAUSE signal from Redis"""
        handler.client = mock_redis_client

        mock_redis_client.xread.return_value = [("scan:control:exec-123", [("1234567890-0", {"action": "PAUSE"})])]

        signal = handler.check_control_signal("exec-123", "0")

        assert signal is not None
        assert signal["action"] == "PAUSE"
        assert signal["_id"] == "1234567890-0"

    def test_check_control_signal_resume(self, handler, mock_redis_client):
        """Test reading RESUME signal from Redis"""
        handler.client = mock_redis_client

        mock_redis_client.xread.return_value = [("scan:control:exec-123", [("1234567890-1", {"action": "RESUME"})])]

        signal = handler.check_control_signal("exec-123", "1234567890-0")

        assert signal is not None
        assert signal["action"] == "RESUME"
        assert signal["_id"] == "1234567890-1"

    def test_update_status_paused(self, handler, mock_redis_client):
        """Test updating status to 'paused'"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-3"

        result = handler.update_status(
            "exec-123", "paused", "Paused by user", {"partial_data": False, "objects_count": 100}
        )

        assert result == "1234567890-3"
        mock_redis_client.xadd.assert_called_once()

    def test_update_status_resuming(self, handler, mock_redis_client):
        """Test updating status to 'resuming'"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-4"

        result = handler.update_status("exec-123", "resuming", "Resumed by user", {"objects_count": 100})

        assert result == "1234567890-4"
        mock_redis_client.xadd.assert_called_once()

    def test_update_status_pausing(self, handler, mock_redis_client):
        """Test updating status to 'pausing' (transitional state)"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-5"

        result = handler.update_status("exec-123", "pausing", "Pausing execution", {"objects_count": 75})

        assert result == "1234567890-5"
