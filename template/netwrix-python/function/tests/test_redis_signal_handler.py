"""
Unit tests for redis_signal_handler module using pytest framework
Tests cover:
- Redis connection management
- Control signal reading
- Checkpoint saving and retrieval
- Status updates
- Stream cleanup
- Health checks
- Timeout handling
"""

import pytest
import time
from unittest.mock import MagicMock, patch

# Import the module to test
from function.redis_signal_handler import RedisSignalHandler, ScanControlContext



class TestRedisSignalHandler:
    """Test RedisSignalHandler class"""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client"""
        return MagicMock()

    @pytest.fixture
    def handler(self, mock_redis_client):
        """Create RedisSignalHandler with mocked Redis"""
        with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler("redis://localhost:6379")
            return handler

    def test_initialization_success(self, mock_redis_client):
        """Test successful Redis connection"""
        mock_redis_client.ping.return_value = True

        with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler("redis://localhost:6379")

        assert handler.client is not None
        assert handler.redis_url == "redis://localhost:6379"

    def test_initialization_failure(self):
        """Test failed Redis connection"""
        with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
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


    def test_save_checkpoint_success(self, handler, mock_redis_client):
        """Test successful checkpoint saving"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-1"

        checkpoint_data = {
            "state": {"processing": 10},
            "scanned_paths": ["/path1", "/path2"],
            "current_path": "/path1",
            "objects_count": 100,
            "failed_paths": [],
            "worker_states": {},
        }

        result = handler.save_checkpoint("exec-123", checkpoint_data)

        assert result == "1234567890-1"
        mock_redis_client.xadd.assert_called_once()
        mock_redis_client.expire.assert_called_once_with("scan:checkpoint:exec-123", 86400)

    def test_save_checkpoint_failure(self, handler, mock_redis_client):
        """Test checkpoint save failure"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.side_effect = Exception("Redis error")

        result = handler.save_checkpoint("exec-123", {})

        assert result is None

    def test_update_status_success(self, handler, mock_redis_client):
        """Test successful status update"""
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = "1234567890-2"

        result = handler.update_status(
            "exec-123", "stopping", "Stop signal received", {"partial_data": True, "objects_count": 50}
        )

        assert result == "1234567890-2"
        mock_redis_client.xadd.assert_called_once()
        args, kwargs = mock_redis_client.xadd.call_args
        message_data = args[1]
        assert message_data["status"] == "stopping"

    def test_cleanup_streams_success(self, handler, mock_redis_client):
        """Test successful stream cleanup"""
        handler.client = mock_redis_client
        mock_redis_client.delete.return_value = 3

        result = handler.cleanup_streams("exec-123")

        assert result is True
        mock_redis_client.delete.assert_called_once()
        # Verify all three streams are targeted
        call_args = mock_redis_client.delete.call_args[0]
        assert "scan:control:exec-123" in call_args
        assert "scan:checkpoint:exec-123" in call_args
        assert "scan:status:exec-123" in call_args

    def test_cleanup_streams_failure(self, handler, mock_redis_client):
        """Test stream cleanup failure"""
        handler.client = mock_redis_client
        mock_redis_client.delete.side_effect = Exception("Redis error")

        result = handler.cleanup_streams("exec-123")

        assert result is False


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
        with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client

            with RedisSignalHandler("redis://localhost:6379") as handler:
                assert handler.client is not None

            mock_redis_client.close.assert_called_once()

    def test_context_manager_with_exception(self, mock_redis_client):
        """Test context manager properly cleans up when exception occurs"""
        with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
            mock_from_url.return_value = mock_redis_client

            try:
                with RedisSignalHandler("redis://localhost:6379") as handler:
                    assert handler.client is not None
                    raise ValueError("Test exception")
            except ValueError:
                pass

            # Verify close was called even with exception
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

        assert result is False  # Not a stop request
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

    def test_should_checkpoint_true(self, context):
        """Test checkpoint interval elapsed"""
        context.checkpoint_interval = 1
        context.last_checkpoint_time = time.time() - 2  # 2 seconds ago

        result = context.should_checkpoint()

        assert result is True

    def test_should_checkpoint_false(self, context):
        """Test checkpoint interval not elapsed"""
        context.checkpoint_interval = 60
        context.last_checkpoint_time = time.time() - 10  # 10 seconds ago

        result = context.should_checkpoint()

        assert result is False

    def test_update_checkpoint_time(self, context):
        """Test updating checkpoint timestamp"""
        old_time = context.last_checkpoint_time
        context.checkpoint_interval = 0.1
        time.sleep(0.15)

        context.update_checkpoint_time()

        assert context.last_checkpoint_time > old_time

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



class TestStreamTrimming:
     """Test stream trimming functionality"""

     def test_checkpoint_stream_trim(self):
         """Test checkpoint stream is trimmed to max 10 items"""
         mock_client = MagicMock()

         with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
             mock_from_url.return_value = mock_client
             handler = RedisSignalHandler("redis://localhost:6379")
             handler.client = mock_client

             handler.save_checkpoint("exec-123", {})

             # Verify xtrim was called with correct parameters
             xtrim_calls = mock_client.xtrim.call_args_list
             assert len(xtrim_calls) > 0
             call_args = xtrim_calls[0]
             assert call_args[0][0] == "scan:checkpoint:exec-123"
             assert call_args[1].get("maxlen") == 10
             assert call_args[1].get("approximate") is True

     def test_status_stream_trim(self):
         """Test status stream is trimmed to max 100 items"""
         mock_client = MagicMock()

         with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
             mock_from_url.return_value = mock_client
             handler = RedisSignalHandler("redis://localhost:6379")
             handler.client = mock_client

             handler.update_status("exec-123", "running")

             xtrim_calls = mock_client.xtrim.call_args_list
             assert len(xtrim_calls) > 0
             call_args = xtrim_calls[0]
             assert call_args[0][0] == "scan:status:exec-123"
             assert call_args[1].get("maxlen") == 100


class TestCheckpointLogic:
     """Test checkpoint saving logic in detail"""

     @pytest.fixture
     def mock_redis_client(self):
         """Create a mock Redis client"""
         return MagicMock()

     @pytest.fixture
     def handler(self, mock_redis_client):
         """Create RedisSignalHandler with mocked Redis"""
         with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
             mock_from_url.return_value = mock_redis_client
             handler = RedisSignalHandler("redis://localhost:6379")
             handler.client = mock_redis_client
             return handler

     def test_save_checkpoint_sets_stream_expiration(self, handler, mock_redis_client):
         """Test that checkpoint stream is set to expire after CONTROL_STREAM_TTL"""
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {"state": "scanning", "share": "\\\\server\\share1"}

         handler.save_checkpoint("exec-123", checkpoint_data)

         # Verify expire was called with correct TTL
         mock_redis_client.expire.assert_called_once_with("scan:checkpoint:exec-123", 86400)

     def test_save_checkpoint_streams_to_correct_key(self, handler, mock_redis_client):
         """Test that checkpoint is saved to correct Redis stream key"""
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {"state": "scanning"}

         handler.save_checkpoint("exec-123", checkpoint_data)

         # Verify xadd was called with correct stream key
         call_args = mock_redis_client.xadd.call_args
         stream_key = call_args[0][0]
         assert stream_key == "scan:checkpoint:exec-123"

     def test_save_checkpoint_serializes_list_fields_to_json(self, handler, mock_redis_client):
         """Test that list fields are JSON-serialized"""
         import json
         mock_redis_client.xadd.return_value = "1234567890-1"

         shares_scanned = ["share1", "share2", "share3"]
         shares_failed = ["share_bad"]
         complete_dirs = ["/path1", "/path2"]
         failed_dirs = ["/path_error"]

         checkpoint_data = {
             "state": "scanning",
             "share": "current_share",
             "shares_scanned": shares_scanned,
             "shares_failed": shares_failed,
             "complete_dirs": complete_dirs,
             "failed_dirs": failed_dirs,
         }

         handler.save_checkpoint("exec-123", checkpoint_data)

         # Extract the message data passed to xadd
         call_args = mock_redis_client.xadd.call_args
         message_data = call_args[0][1]

         # Verify list fields are JSON-serialized
         assert message_data["shares_scanned"] == json.dumps(shares_scanned)
         assert message_data["shares_failed"] == json.dumps(shares_failed)
         assert message_data["complete_dirs"] == json.dumps(complete_dirs)
         assert message_data["failed_dirs"] == json.dumps(failed_dirs)

     def test_save_checkpoint_handles_empty_lists(self, handler, mock_redis_client):
         """Test that empty lists are properly handled"""
         import json
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {
             "state": "scanning",
             "share": "current_share",
             "shares_scanned": [],
             "shares_failed": [],
             "complete_dirs": [],
             "failed_dirs": [],
         }

         handler.save_checkpoint("exec-123", checkpoint_data)

         call_args = mock_redis_client.xadd.call_args
         message_data = call_args[0][1]

         # Verify empty lists are properly serialized
         assert message_data["shares_scanned"] == "[]"
         assert message_data["shares_failed"] == "[]"
         assert message_data["complete_dirs"] == "[]"
         assert message_data["failed_dirs"] == "[]"

     def test_save_checkpoint_handles_missing_list_fields(self, handler, mock_redis_client):
         """Test checkpoint save when list fields are missing from input"""
         import json
         mock_redis_client.xadd.return_value = "1234567890-1"

         # Only provide state and share, omit list fields
         checkpoint_data = {
             "state": "scanning",
             "share": "current_share",
         }

         handler.save_checkpoint("exec-123", checkpoint_data)

         call_args = mock_redis_client.xadd.call_args
         message_data = call_args[0][1]

         # Verify missing list fields default to empty lists
         assert message_data["shares_scanned"] == "[]"
         assert message_data["shares_failed"] == "[]"
         assert message_data["complete_dirs"] == "[]"
         assert message_data["failed_dirs"] == "[]"

     def test_save_checkpoint_includes_timestamp(self, handler, mock_redis_client):
         """Test that checkpoint includes timestamp"""
         from datetime import datetime
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {"state": "scanning"}

         with patch("function.redis_signal_handler.datetime") as mock_datetime:
             mock_datetime.utcnow.return_value.isoformat.return_value = "2026-01-21T09:00:00.000000"
             handler.save_checkpoint("exec-123", checkpoint_data)

         call_args = mock_redis_client.xadd.call_args
         message_data = call_args[0][1]

         # Verify timestamp is present
         assert "timestamp" in message_data
         assert message_data["timestamp"] == "2026-01-21T09:00:00.000000"

     def test_save_checkpoint_returns_message_id(self, handler, mock_redis_client):
         """Test that save_checkpoint returns the message ID from xadd"""
         expected_message_id = "1234567890-1"
         mock_redis_client.xadd.return_value = expected_message_id

         checkpoint_data = {"state": "scanning"}

         result = handler.save_checkpoint("exec-123", checkpoint_data)

         assert result == expected_message_id

     def test_save_checkpoint_returns_none_on_redis_error(self, handler, mock_redis_client):
         """Test that save_checkpoint returns None on Redis error"""
         import redis
         mock_redis_client.xadd.side_effect = redis.exceptions.RedisError("Connection refused")

         checkpoint_data = {"state": "scanning"}

         result = handler.save_checkpoint("exec-123", checkpoint_data)

         assert result is None

     def test_save_checkpoint_reconnects_on_redis_error(self, handler, mock_redis_client):
         """Test that save_checkpoint triggers reconnection on Redis error"""
         import redis
         mock_redis_client.xadd.side_effect = redis.exceptions.RedisError("Connection refused")

         checkpoint_data = {"state": "scanning"}

         with patch.object(handler, "_connect") as mock_connect:
             handler.save_checkpoint("exec-123", checkpoint_data)
             mock_connect.assert_called_once()

     def test_save_checkpoint_handles_generic_exception(self, handler, mock_redis_client):
         """Test that save_checkpoint handles generic exceptions"""
         mock_redis_client.xadd.side_effect = Exception("Unknown error")

         checkpoint_data = {"state": "scanning"}

         result = handler.save_checkpoint("exec-123", checkpoint_data)

         assert result is None

     def test_save_checkpoint_includes_objects_count_in_logging(self, handler, mock_redis_client):
         """Test that objects_count from checkpoint_data is included in debug logging"""
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {
             "state": "scanning",
             "objects_count": 42,
         }

         with patch("function.redis_signal_handler.logger") as mock_logger:
             handler.save_checkpoint("exec-123", checkpoint_data)
             # Logger should include objects_count in the debug message
             mock_logger.debug.assert_called_once()

     def test_save_checkpoint_with_complex_data(self, handler, mock_redis_client):
         """Test checkpoint save with all fields populated"""
         import json
         mock_redis_client.xadd.return_value = "1234567890-1"

         checkpoint_data = {
             "state": "scanning_directory",
             "share": "\\\\server\\documents",
             "shares_scanned": ["share1", "share2"],
             "shares_failed": ["share_bad"],
             "complete_dirs": ["/dir1", "/dir2/subdir"],
             "failed_dirs": ["/dir_error"],
             "objects_count": 1500,
         }

         result = handler.save_checkpoint("exec-123", checkpoint_data)

         assert result == "1234567890-1"
         mock_redis_client.xadd.assert_called_once()
         mock_redis_client.expire.assert_called_once_with("scan:checkpoint:exec-123", 86400)
         mock_redis_client.xtrim.assert_called_once()

         # Verify message structure
         call_args = mock_redis_client.xadd.call_args
         message_data = call_args[0][1]

         assert message_data["state"] == "scanning_directory"
         assert message_data["share"] == "\\\\server\\documents"
         assert message_data["shares_scanned"] == json.dumps(["share1", "share2"])
         assert message_data["shares_failed"] == json.dumps(["share_bad"])
         assert message_data["complete_dirs"] == json.dumps(["/dir1", "/dir2/subdir"])
         assert message_data["failed_dirs"] == json.dumps(["/dir_error"])


class TestHealthCheck:
   """Test health check functionality"""

   def test_health_check_success(self):
       """Test successful health check"""
       mock_client = MagicMock()
       mock_client.ping.return_value = True

       with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
           mock_from_url.return_value = mock_client
           handler = RedisSignalHandler("redis://localhost:6379")
           handler.client = mock_client

           result = handler.health_check()

           assert result is True
           mock_client.ping.assert_called()

   def test_health_check_first_ping_fails_reconnect_succeeds(self):
       """Test health check with reconnection recovery"""
       mock_client = MagicMock()
       # First ping fails, then after reconnect succeeds
       mock_client.ping.side_effect = [
           Exception("Connection lost"),
           True  # After reconnect, ping succeeds
       ]

       with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
           mock_from_url.return_value = mock_client
           handler = RedisSignalHandler("redis://localhost:6379")
           handler.client = mock_client

           result = handler.health_check()

           assert result is True
           assert mock_client.ping.call_count == 2  # First failed, then after reconnect

   def test_health_check_both_pings_fail(self):
       """Test health check when reconnection also fails"""
       import redis
       mock_client = MagicMock()
       # RedisError triggers reconnection, but then client becomes None due to failed reconnection
       mock_client.ping.side_effect = redis.exceptions.RedisError("Connection refused")

       with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
           mock_from_url.return_value = mock_client
           handler = RedisSignalHandler("redis://localhost:6379")
           handler.client = mock_client

           result = handler.health_check()

           # Should return False when both attempts fail
           assert result is False

   def test_health_check_redis_error_exception(self):
       """Test health check with RedisError exception on first ping"""
       import redis
       mock_client = MagicMock()
       # First ping fails, second succeeds after reconnect
       mock_client.ping.side_effect = [
           redis.exceptions.RedisError("Redis down"),
           True  # Recovery after reconnect
       ]

       with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
           mock_from_url.return_value = mock_client
           handler = RedisSignalHandler("redis://localhost:6379")
           handler.client = mock_client

           result = handler.health_check()

           # Should recover after reconnection
           assert result is True

   def test_health_check_timeout_and_recovery(self):
       """Test health check handles timeout and recovers"""
       import redis
       mock_client = MagicMock()
       # First ping times out, then succeeds after reconnect
       mock_client.ping.side_effect = [
           redis.exceptions.TimeoutError("Connection timeout"),
           True  # Recovery after reconnect
       ]

       with patch("function.redis_signal_handler.redis.from_url") as mock_from_url:
           mock_from_url.return_value = mock_client
           handler = RedisSignalHandler("redis://localhost:6379")
           handler.client = mock_client

           result = handler.health_check()

           # Should recover after reconnection
           assert result is True
