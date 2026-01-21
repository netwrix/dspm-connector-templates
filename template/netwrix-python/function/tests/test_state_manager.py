"""
Unit tests for state_manager module using pytest framework
Tests cover:
- State manager initialization
- State transitions
- Signal checking
- Checkpoint management
- Callback triggering
- Error handling and degradation
"""

import pytest
import time
from unittest.mock import MagicMock, patch

from function.state_manager import StateManager


class TestStateManagerInitialization:
    """Test StateManager initialization"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    def test_initialization_with_defaults(self, mock_context):
        """Test initialization with default parameters"""
        manager = StateManager(context=mock_context)

        assert manager.context == mock_context
        assert manager.current_state == "running"
        assert manager.requested_state is None
        assert manager.redis_handler is None
        assert manager.supported_states == {"stop": True, "pause": False, "resume": False}

    def test_initialization_with_custom_states(self, mock_context):
        """Test initialization with custom supported states"""
        custom_states = {"stop": True, "pause": True, "resume": True}
        manager = StateManager(context=mock_context, supported_states=custom_states)

        assert manager.supported_states == custom_states

    def test_initialization_with_custom_intervals(self, mock_context):
        """Test initialization with custom check intervals"""
        manager = StateManager(context=mock_context, checkpoint_interval=30, signal_check_interval=3)

        assert manager.checkpoint_interval == 30
        assert manager.signal_check_interval == 3

    def test_initialize_redis_success(self, mock_context):
        """Test successful Redis initialization"""
        manager = StateManager(context=mock_context)

        with patch("function.state_manager.RedisSignalHandler") as mock_handler_class:
            with patch("function.state_manager.ScanControlContext") as mock_context_class:
                mock_handler = MagicMock()
                mock_handler.health_check.return_value = True
                mock_handler_class.return_value = mock_handler

                mock_control = MagicMock()
                mock_context_class.return_value = mock_control

                result = manager.initialize()

        assert result is True
        assert manager.redis_handler is not None
        assert manager.control_context is not None

    def test_initialize_redis_unavailable(self, mock_context):
        """Test Redis initialization when Redis is unavailable"""
        manager = StateManager(context=mock_context)

        with patch("function.state_manager.RedisSignalHandler") as mock_handler_class:
            mock_handler = MagicMock()
            mock_handler.health_check.return_value = False
            mock_handler_class.return_value = mock_handler

            result = manager.initialize()

        assert result is False
        assert manager.control_context is None

    def test_initialize_no_execution_id(self, mock_context):
        """Test initialization when no execution ID is available"""
        mock_context.scan_execution_id = None
        mock_context.sync_execution_id = None

        manager = StateManager(context=mock_context)
        result = manager.initialize()

        assert result is False


class TestStateTransitions:
    """Test state transition logic"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_set_state_valid_transition_running_to_stopping(self, manager):
        """Test valid state transition: running -> stopping"""
        manager.current_state = "running"

        result = manager.set_state("stopping")

        assert result is True
        assert manager.current_state == "stopping"

    def test_set_state_valid_transition_stopping_to_stopped(self, manager):
        """Test valid state transition: stopping -> stopped"""
        manager.current_state = "stopping"

        result = manager.set_state("stopped")

        assert result is True
        assert manager.current_state == "stopped"

    def test_set_state_invalid_transition(self, manager):
        """Test invalid state transition"""
        manager.current_state = "stopped"

        result = manager.set_state("running")

        assert result is False
        assert manager.current_state == "stopped"

    def test_set_state_callback_triggered(self, manager):
        """Test state change callback is triggered"""
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        manager.set_state("stopping")

        # Callback should be called outside lock
        callback.assert_called()

    def test_supports_state(self, manager):
        """Test supports_state method"""
        assert manager.supports_state("stop") is True
        assert manager.supports_state("pause") is False
        assert manager.supports_state("resume") is False

    def test_get_supported_states(self, manager):
        """Test getting supported states"""
        states = manager.get_supported_states()

        assert states == {"stop": True, "pause": False, "resume": False}

    def test_get_current_state(self, manager):
        """Test getting current state"""
        assert manager.get_current_state() == "running"

        manager.current_state = "stopping"
        assert manager.get_current_state() == "stopping"

    def test_callback_receives_different_old_and_new_states(self, manager):
        """Test that callback receives distinct old_state and new_state values

        This is a regression test for a bug where _trigger_state_change_callbacks
        was called with self.current_state and new_state being the same value
        because the state was already updated before calling the callbacks.
        """
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        # Transition from 'running' to 'stopping'
        manager.set_state("stopping")

        # Callback should be called with (old_state='running', new_state='stopping')
        # NOT (old_state='stopping', new_state='stopping')
        callback.assert_called_once()
        args = callback.call_args[0]
        old_state, new_state = args

        assert old_state == "running", f"Expected old_state='running' but got '{old_state}'"
        assert new_state == "stopping", f"Expected new_state='stopping' but got '{new_state}'"
        assert old_state != new_state, "old_state and new_state should be different"

    def test_multiple_transitions_have_correct_old_states(self, manager):
        """Test that multiple state transitions pass correct old states to callbacks"""
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        # First transition: running -> stopping
        manager.set_state("stopping")
        first_call_args = callback.call_args_list[0][0]
        assert first_call_args[0] == "running"
        assert first_call_args[1] == "stopping"

        # Second transition: stopping -> stopped
        callback.reset_mock()
        manager.set_state("stopped")
        second_call_args = callback.call_args_list[0][0]
        assert second_call_args[0] == "stopping"
        assert second_call_args[1] == "stopped"

    def test_callback_receives_distinct_states_in_running_to_completed_transition(self, manager):
        """Test callback with running -> completed transition"""
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        manager.set_state("completed")

        callback.assert_called_once()
        old_state, new_state = callback.call_args[0]
        assert old_state == "running"
        assert new_state == "completed"
        assert old_state != new_state


class TestSignalChecking:
    """Test signal checking functionality"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_check_for_state_changes_no_control_context(self, manager):
        """Test checking state changes when control context is None"""
        manager.control_context = None

        result = manager.check_for_state_changes()

        assert result is False

    def test_check_for_state_changes_interval_not_reached(self, manager):
        """Test that checks respect signal check interval"""
        manager.control_context = MagicMock()
        manager.last_signal_check = time.time()
        manager.signal_check_interval = 5

        result = manager.check_for_state_changes()

        assert result is False
        manager.control_context.check_for_signals.assert_not_called()

    def test_check_for_state_changes_stop_signal(self, manager):
        """Test detecting STOP signal"""
        mock_control = MagicMock()
        mock_control.check_for_signals.return_value = True
        mock_control.stop_requested = True
        manager.control_context = mock_control
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.check_for_state_changes()

        assert result is True
        assert manager.requested_state == "stop"
        assert manager.current_state == "stopping"

    def test_check_for_state_changes_no_signal(self, manager):
        """Test when no signal is received"""
        mock_control = MagicMock()
        mock_control.check_for_signals.return_value = False
        manager.control_context = mock_control
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.check_for_state_changes()

        assert result is False
        assert manager.requested_state is None

    def test_check_for_state_changes_redis_timeout(self, manager):
        """Test handling Redis timeout"""
        mock_control = MagicMock()
        mock_control.check_for_signals.side_effect = Exception("Redis timeout")
        manager.control_context = mock_control
        manager.redis_handler = MagicMock()
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.check_for_state_changes()

        assert result is False


class TestCheckpointManagement:
    """Test checkpoint saving and retrieval"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_should_checkpoint_false_initially(self, manager):
        """Test that checkpoint interval hasn't elapsed initially"""
        result = manager.should_checkpoint()

        assert result is False

    def test_should_checkpoint_true_after_interval(self, manager):
        """Test that checkpoint is needed after interval"""
        manager.checkpoint_interval = 0.1
        manager.last_checkpoint = time.time() - 0.2

        result = manager.should_checkpoint()

        assert result is True

    def test_save_checkpoint_success(self, manager):
        """Test successful checkpoint saving"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.return_value = "checkpoint-123"
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()

        checkpoint_data = {"progress": 50, "timestamp": "2026-01-16T09:00:00Z"}
        result = manager.save_checkpoint(checkpoint_data)

        assert result == "checkpoint-123"
        assert manager.last_checkpoint > 0

    def test_save_checkpoint_no_handler(self, manager):
        """Test checkpoint save when redis handler is None"""
        manager.redis_handler = None

        result = manager.save_checkpoint({"progress": 50})

        assert result is None

    def test_save_checkpoint_exception(self, manager):
        """Test checkpoint save with exception"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.side_effect = Exception("Save failed")
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()

        result = manager.save_checkpoint({"progress": 50})

        assert result is None


class TestShutdown:
    """Test shutdown functionality"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_shutdown_stopped_status(self, manager):
        """Test shutdown with stopped status"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler

        result = manager.shutdown("stopped")

        assert result is True
        assert manager.current_state == "stopped"
        assert manager.is_shutdown() is True

    def test_shutdown_completed_status(self, manager):
        """Test shutdown with completed status"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler

        result = manager.shutdown("completed")

        assert result is True
        assert manager.current_state == "completed"

    def test_shutdown_no_handler(self, manager):
        """Test shutdown when no redis handler available"""
        manager.redis_handler = None

        result = manager.shutdown("stopped")

        # Should still transition state
        assert result is True
        assert manager.current_state == "stopped"

    def test_shutdown_cleanup_called(self, manager):
        """Test that cleanup_streams is called"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler

        manager.shutdown("stopped")

        mock_handler.cleanup_streams.assert_called_once_with("scan-123")

    def test_is_shutdown_false_initially(self, manager):
        """Test is_shutdown is False initially"""
        assert manager.is_shutdown() is False

    def test_is_shutdown_true_after_shutdown(self, manager):
        """Test is_shutdown is True after shutdown"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler

        manager.shutdown("stopped")

        assert manager.is_shutdown() is True


class TestCallbackManagement:
    """Test state change callback functionality"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_on_state_change_registration(self, manager):
        """Test registering state change callback"""
        callback = MagicMock()
        manager.on_state_change(callback)

        assert len(manager._on_state_change_callbacks) == 1

    def test_on_state_change_triggered(self, manager):
        """Test callback is triggered on state change"""
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        manager.set_state("stopping")

        callback.assert_called_once()

    def test_multiple_callbacks(self, manager):
        """Test multiple callbacks are triggered"""
        callback1 = MagicMock()
        callback2 = MagicMock()

        manager.on_state_change(callback1)
        manager.on_state_change(callback2)
        manager.current_state = "running"

        manager.set_state("stopping")

        callback1.assert_called_once()
        callback2.assert_called_once()

    def test_callback_exception_handling(self, manager):
        """Test that callback exception doesn't break others"""
        callback1 = MagicMock(side_effect=Exception("Callback error"))
        callback2 = MagicMock()

        manager.on_state_change(callback1)
        manager.on_state_change(callback2)
        manager.current_state = "running"

        # Should not raise
        manager.set_state("stopping")

        # Both callbacks should have been called
        callback1.assert_called_once()
        callback2.assert_called_once()


class TestStateManagerClose:
    """Test resource cleanup"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_close_with_handler(self, manager):
        """Test closing with active redis handler"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler

        manager.close()

        mock_handler.close.assert_called_once()

    def test_close_without_handler(self, manager):
        """Test closing when handler is None"""
        manager.redis_handler = None

        # Should not raise
        manager.close()


class TestShouldStop:
    """Test should_stop method"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_should_stop_false_initially(self, manager):
        """Test should_stop returns False initially"""
        result = manager.should_stop()

        assert result is False

    def test_should_stop_true_after_stop_request(self, manager):
        """Test should_stop returns True after stop request"""
        manager.requested_state = "stop"

        result = manager.should_stop()

        assert result is True


class TestShouldPause:
    """Test should_pause method"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_should_pause_unsupported(self, manager):
        """Test should_pause returns False when pause is unsupported"""
        manager.supported_states["pause"] = False

        result = manager.should_pause()

        assert result is False

    def test_should_pause_supported_but_not_requested(self, manager):
        """Test should_pause when pause is supported but not requested"""
        manager.supported_states["pause"] = True
        manager.control_context = MagicMock()
        manager.control_context.pause_requested = False

        result = manager.should_pause()

        assert result is False


class TestCheckpointIntegration:
    """Test checkpoint integration with StateManager and RedisSignalHandler"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager instance"""
        return StateManager(context=mock_context)

    def test_save_checkpoint_with_full_state_data(self, manager):
        """Test saving checkpoint with complete state information"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.return_value = "checkpoint-msg-123"
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()

        checkpoint_data = {
            "state": "scanning_directory",
            "share": "\\\\server\\share1",
            "shares_scanned": ["share1"],
            "shares_failed": [],
            "complete_dirs": ["/path1", "/path2"],
            "failed_dirs": [],
            "objects_count": 150,
        }

        result = manager.save_checkpoint(checkpoint_data)

        assert result == "checkpoint-msg-123"
        mock_handler.save_checkpoint.assert_called_once_with("scan-123", checkpoint_data)

    def test_save_checkpoint_updates_last_checkpoint_time(self, manager):
        """Test that save_checkpoint updates the last checkpoint timestamp"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.return_value = "checkpoint-msg-123"
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()
        manager.last_checkpoint = 0

        checkpoint_data = {"state": "scanning"}

        manager.save_checkpoint(checkpoint_data)

        assert manager.last_checkpoint > 0

    def test_should_checkpoint_respects_interval(self, manager):
        """Test that should_checkpoint respects configured interval"""
        manager.checkpoint_interval = 60
        manager.last_checkpoint = time.time() - 30  # 30 seconds ago

        result = manager.should_checkpoint()

        assert result is False  # Not yet time for checkpoint

    def test_should_checkpoint_triggers_after_interval(self, manager):
        """Test that should_checkpoint triggers after interval elapses"""
        manager.checkpoint_interval = 1
        manager.last_checkpoint = time.time() - 2  # 2 seconds ago

        result = manager.should_checkpoint()

        assert result is True  # Time for checkpoint

    def test_checkpoint_workflow_with_scan_progress(self, manager):
        """Test complete checkpoint workflow tracking scan progress"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.return_value = "checkpoint-1"
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()

        # First checkpoint - initial share
        checkpoint1 = {
            "state": "scanning_share",
            "share": "share1",
            "shares_scanned": [],
            "shares_failed": [],
            "complete_dirs": ["/dir1"],
            "failed_dirs": [],
            "objects_count": 50,
        }

        result1 = manager.save_checkpoint(checkpoint1)
        assert result1 == "checkpoint-1"

        # Simulate more time passing
        manager.last_checkpoint = time.time() - 100
        assert manager.should_checkpoint() is True

        # Second checkpoint - share completed
        mock_handler.save_checkpoint.return_value = "checkpoint-2"
        checkpoint2 = {
            "state": "scanning_share",
            "share": "share2",
            "shares_scanned": ["share1"],
            "shares_failed": [],
            "complete_dirs": [],
            "failed_dirs": [],
            "objects_count": 100,
        }

        result2 = manager.save_checkpoint(checkpoint2)
        assert result2 == "checkpoint-2"

        # Verify both checkpoints were saved
        assert mock_handler.save_checkpoint.call_count == 2

    def test_checkpoint_with_failed_shares(self, manager):
        """Test checkpoint saving tracks failed shares"""
        mock_handler = MagicMock()
        mock_handler.save_checkpoint.return_value = "checkpoint-123"
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()

        checkpoint_data = {
            "state": "scanning",
            "share": "share3",
            "shares_scanned": ["share1", "share2"],
            "shares_failed": ["share_inaccessible"],
            "complete_dirs": ["/path1"],
            "failed_dirs": ["/denied_path"],
            "objects_count": 75,
        }

        result = manager.save_checkpoint(checkpoint_data)

        assert result == "checkpoint-123"
        mock_handler.save_checkpoint.assert_called_once_with("scan-123", checkpoint_data)

    def test_save_checkpoint_without_redis_handler(self, manager):
        """Test checkpoint save gracefully handles missing redis handler"""
        manager.redis_handler = None

        checkpoint_data = {"state": "scanning"}

        result = manager.save_checkpoint(checkpoint_data)

        # Should return None but not raise exception
        assert result is None

    def test_multiple_checkpoints_increase_objects_count(self, manager):
        """Test realistic workflow where objects_count increases across checkpoints"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        manager.control_context = MagicMock()
        checkpoint_ids = ["cp-1", "cp-2", "cp-3"]
        mock_handler.save_checkpoint.side_effect = checkpoint_ids

        # First checkpoint
        cp1 = {
            "state": "scanning",
            "objects_count": 100,
            "complete_dirs": ["/dir1"],
        }
        result1 = manager.save_checkpoint(cp1)
        assert result1 == "cp-1"

        # Second checkpoint (more objects found)
        cp2 = {
            "state": "scanning",
            "objects_count": 250,
            "complete_dirs": ["/dir1", "/dir2"],
        }
        result2 = manager.save_checkpoint(cp2)
        assert result2 == "cp-2"

        # Third checkpoint (even more objects)
        cp3 = {
            "state": "scanning",
            "objects_count": 500,
            "complete_dirs": ["/dir1", "/dir2", "/dir3"],
        }
        result3 = manager.save_checkpoint(cp3)
        assert result3 == "cp-3"

        # Verify all were saved
        assert mock_handler.save_checkpoint.call_count == 3
