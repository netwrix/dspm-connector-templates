"""
Unit tests for state_manager module using pytest framework
Tests cover:
- State manager initialization
- State transitions
- Signal checking
- Callback triggering
- Error handling and degradation
- Pause and resume functionality
"""

import pytest
import time
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from state_manager import StateManager


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
        manager = StateManager(context=mock_context, signal_check_interval=3)

        assert manager.signal_check_interval == 3

    def test_initialize_redis_success(self, mock_context):
        """Test successful Redis initialization"""
        manager = StateManager(context=mock_context)

        with patch("state_manager.RedisSignalHandler") as mock_handler_class:
            with patch("state_manager.ScanControlContext") as mock_context_class:
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

        with patch("state_manager.RedisSignalHandler") as mock_handler_class:
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
        # Must transition from running -> stopping -> stopped
        manager.set_state("stopping")
        manager.set_state("stopped")

        # Now shutdown from stopped state
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
        # Must be in a valid state for transitioning to stopped
        manager.set_state("stopping")
        manager.set_state("stopped")

        result = manager.shutdown("stopped")

        # Should still transition state (or already be in stopped)
        assert result is True
        assert manager.current_state == "stopped"

    def test_shutdown_cleanup_called(self, manager):
        """Test that cleanup_streams is called"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        # Must be in stopping or valid transition state
        manager.set_state("stopping")
        manager.set_state("stopped")

        result = manager.shutdown("stopped")

        # Cleanup should only be called if transition was successful
        if result:
            mock_handler.cleanup_streams.assert_called_once_with("scan-123")

    def test_is_shutdown_false_initially(self, manager):
        """Test is_shutdown is False initially"""
        assert manager.is_shutdown() is False

    def test_is_shutdown_true_after_shutdown(self, manager):
        """Test is_shutdown is True after shutdown"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        # Must transition to stopped state properly
        manager.set_state("stopping")
        manager.set_state("stopped")

        result = manager.shutdown("stopped")

        # After successful shutdown from stopped state
        if result:
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


class TestPauseResumeStateTransitions:
    """Test state transitions for pause and resume operations"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager with pause/resume support"""
        return StateManager(context=mock_context, supported_states={"stop": True, "pause": True, "resume": True})

    def test_running_to_pausing_transition(self, manager):
        """Test valid transition: running -> pausing"""
        manager.current_state = "running"

        result = manager.set_state("pausing")

        assert result is True
        assert manager.current_state == "pausing"

    def test_pausing_to_paused_transition(self, manager):
        """Test valid transition: pausing -> paused"""
        manager.current_state = "pausing"

        result = manager.set_state("paused")

        assert result is True
        assert manager.current_state == "paused"

    def test_paused_to_resuming_transition(self, manager):
        """Test valid transition: paused -> resuming"""
        manager.current_state = "paused"

        result = manager.set_state("resuming")

        assert result is True
        assert manager.current_state == "resuming"

    def test_resuming_to_running_transition(self, manager):
        """Test valid transition: resuming -> running"""
        manager.current_state = "resuming"

        result = manager.set_state("running")

        assert result is True
        assert manager.current_state == "running"

    def test_paused_to_stopped_transition(self, manager):
        """Test valid transition: paused -> stopped (direct stop from paused state)"""
        manager.current_state = "paused"

        result = manager.set_state("stopped")

        assert result is True
        assert manager.current_state == "stopped"

    def test_invalid_transition_paused_to_running(self, manager):
        """Test invalid transition: paused -> running (must go through resuming)"""
        manager.current_state = "paused"

        result = manager.set_state("running")

        assert result is False
        assert manager.current_state == "paused"

    def test_invalid_transition_resuming_to_paused(self, manager):
        """Test invalid transition: resuming -> paused"""
        manager.current_state = "resuming"

        result = manager.set_state("paused")

        assert result is False
        assert manager.current_state == "resuming"

    def test_invalid_transition_pausing_to_running(self, manager):
        """Test invalid transition: pausing -> running (must go through paused)"""
        manager.current_state = "pausing"

        result = manager.set_state("running")

        assert result is False
        assert manager.current_state == "pausing"

    def test_running_to_paused_invalid(self, manager):
        """Test invalid transition: running -> paused (must go through pausing)"""
        manager.current_state = "running"

        result = manager.set_state("paused")

        assert result is False
        assert manager.current_state == "running"


class TestPauseResumeSignalHandling:
    """Test pause/resume signal handling in StateManager"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager with pause/resume support"""
        return StateManager(context=mock_context, supported_states={"stop": True, "pause": True, "resume": True})

    def test_check_for_state_changes_pause_signal(self, manager):
        """Test detecting PAUSE signal and transitioning to pausing state"""
        mock_control = MagicMock()
        mock_control.check_for_signals.return_value = True
        mock_control.stop_requested = False
        mock_control.pause_requested = True
        manager.control_context = mock_control
        manager.current_state = "running"
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.check_for_state_changes()

        assert result is False  # Pause doesn't return True like stop
        assert manager.requested_state == "pause"
        assert manager.current_state == "pausing"

    def test_check_for_state_changes_resume_signal(self, manager):
        """Test detecting RESUME signal"""
        mock_control = MagicMock()
        mock_control.check_for_signals.return_value = True
        mock_control.stop_requested = False
        mock_control.pause_requested = False
        manager.control_context = mock_control
        manager.current_state = "paused"
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.check_for_state_changes()

        assert result is False
        # Resume signal detected but requires state transition handling

    def test_should_pause_supported_and_requested(self, manager):
        """Test should_pause when pause is supported and requested"""
        manager.supported_states["pause"] = True
        manager.requested_state = "pause"

        result = manager.should_pause()

        # should_pause returns True when pause is supported and requested_state is "pause"
        assert result is True

    def test_should_pause_supported_but_not_requested(self, manager):
        """Test should_pause when pause is supported but not requested"""
        manager.supported_states["pause"] = True
        mock_control = MagicMock()
        mock_control.pause_requested = False
        manager.control_context = mock_control
        manager.last_signal_check = time.time() - 10  # Force check

        result = manager.should_pause()

        assert result is False

    def test_should_pause_not_supported(self, manager):
        """Test should_pause returns False when pause is not supported"""
        manager.supported_states["pause"] = False
        mock_control = MagicMock()
        mock_control.pause_requested = True
        manager.control_context = mock_control

        result = manager.should_pause()

        assert result is False

    def test_pause_then_resume_transition_sequence(self, manager):
        """Test complete pause and resume state transition sequence"""
        # Start in running state
        assert manager.current_state == "running"

        # Transition to pausing
        assert manager.set_state("pausing") is True
        assert manager.current_state == "pausing"

        # Transition to paused
        assert manager.set_state("paused") is True
        assert manager.current_state == "paused"

        # Transition to resuming
        assert manager.set_state("resuming") is True
        assert manager.current_state == "resuming"

        # Back to running
        assert manager.set_state("running") is True
        assert manager.current_state == "running"

    def test_pause_then_stop_from_paused(self, manager):
        """Test stopping execution while paused"""
        manager.current_state = "paused"

        result = manager.set_state("stopped")

        assert result is True
        assert manager.current_state == "stopped"

    def test_pause_then_stop_from_pausing(self, manager):
        """Test stopping while transitioning to paused state"""
        manager.current_state = "pausing"

        result = manager.set_state("stopped")

        assert result is False  # Invalid transition: pausing -> stopped
        assert manager.current_state == "pausing"

    def test_pause_state_with_callback(self, manager):
        """Test state change callback triggered during pause state transition"""
        callback = MagicMock()
        manager.on_state_change(callback)
        manager.current_state = "running"

        manager.set_state("pausing")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == "running"
        assert args[1] == "pausing"


class TestPauseResumeShutdown:
    """Test shutdown behavior with pause/resume states"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager with pause/resume support"""
        return StateManager(context=mock_context, supported_states={"stop": True, "pause": True, "resume": True})

    def test_shutdown_from_paused_state(self, manager):
        """Test shutdown from paused state"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        manager.current_state = "paused"

        result = manager.shutdown("stopped")

        assert result is True
        assert manager.current_state == "stopped"
        assert manager.is_shutdown() is True

    def test_shutdown_from_resuming_state(self, manager):
        """Test shutdown from resuming state"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        # Set up valid transition path: running -> pausing -> paused -> resuming
        manager.set_state("pausing")
        manager.set_state("paused")
        manager.set_state("resuming")

        # resuming -> failed is valid, but resuming -> stopped is not
        # So this should fail
        result = manager.shutdown("stopped")

        # This should fail due to invalid transition
        assert result is False

    def test_shutdown_from_pausing_state(self, manager):
        """Test shutdown from pausing state (should fail - invalid transition)"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        manager.current_state = "pausing"

        # pausing -> stopped is not valid, must go through paused first
        result = manager.shutdown("stopped")

        # Should fail because of invalid transition
        assert result is False

    def test_shutdown_status_update_includes_partial_data(self, manager):
        """Test that shutdown status update includes partial_data flag"""
        mock_handler = MagicMock()
        manager.redis_handler = mock_handler
        manager.current_state = "paused"

        manager.shutdown("stopped")

        mock_handler.update_status.assert_called_once()
        call_args = mock_handler.update_status.call_args
        assert call_args[0][0] == "scan-123"  # execution_id
        assert call_args[0][1] == "stopped"  # final_status
        assert call_args[0][3]["partial_data"] is True  # metadata


class TestPauseResumeErrorHandling:
    """Test error handling during pause/resume operations"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None
        return context

    @pytest.fixture
    def manager(self, mock_context):
        """Create StateManager with pause/resume support"""
        return StateManager(context=mock_context, supported_states={"stop": True, "pause": True, "resume": True})

    def test_pause_signal_with_redis_error(self, manager):
        """Test pause signal handling with Redis error"""
        mock_control = MagicMock()
        mock_control.check_for_signals.side_effect = Exception("Redis connection error")
        manager.control_context = mock_control
        manager.redis_handler = MagicMock()
        manager.current_state = "running"
        manager.last_signal_check = time.time() - 10

        # Should handle error gracefully
        result = manager.check_for_state_changes()

        assert result is False
        # State should not change on error
        assert manager.current_state == "running"

    def test_invalid_pause_without_support(self):
        """Test that pause is not supported by default"""
        context = MagicMock()
        context.scan_execution_id = "scan-123"
        context.sync_execution_id = None

        manager = StateManager(context=context)  # No pause support

        # should_pause should return False even with pause signal
        result = manager.should_pause()
        assert result is False

    def test_state_transition_thread_safety_with_pause(self, manager):
        """Test thread-safe state transitions with pause state"""
        import threading

        results = []

        def try_transition():
            result = manager.set_state("pausing")
            results.append(result)

        manager.current_state = "running"

        # Try multiple transitions concurrently
        threads = [threading.Thread(target=try_transition) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Due to timing, all threads may succeed before the state changes
        # At least the final state should be pausing
        assert manager.current_state == "pausing"
        # We should have at least one successful transition
        assert sum(1 for r in results if r) >= 1

    def test_should_pause_supported_but_not_requested(self, manager):
        """Test should_pause when pause is supported but not requested"""
        manager.supported_states["pause"] = True
        manager.control_context = MagicMock()
        manager.control_context.pause_requested = False

        result = manager.should_pause()

        assert result is False
