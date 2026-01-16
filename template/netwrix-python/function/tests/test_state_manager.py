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
        # Context should be disabled
        assert manager.control_context is None
        assert manager.redis_handler is None


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
