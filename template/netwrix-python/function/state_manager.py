"""
State Management Framework for OpenFaaS Connectors

This module provides a framework for managing scan/sync execution states,
including stop/pause/resume operations. Connectors can declare their
supported states and hook into state transition events.

Note: Uses `from __future__ import annotations` for forward type references.

Usage:
    class MyConnectorHandler:
        def __init__(self, context):
            self.state_manager = StateManager(
                context=context,
                supported_states={
                    'stop': True,      # This connector supports stopping
                    'pause': False,    # This connector doesn't support pausing
                    'resume': False    # This connector doesn't support resuming
                }
            )

        def handle(self, event, context):
            # Initialize state monitoring
            self.state_manager.initialize()

            # In main loop:
            if self.state_manager.should_stop():
                self.state_manager.shutdown()
                return result

            # Periodically save progress:
            if self.state_manager.should_checkpoint():
                self.state_manager.save_checkpoint({
                    'progress': current_progress,
                    'timestamp': datetime.now().isoformat()
                })
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional, Dict, Any, Callable

# Import here to allow for easier mocking in tests
from function.redis_signal_handler import RedisSignalHandler, ScanControlContext

logger = logging.getLogger(__name__)


class StateManager:
    """
    Manages connector execution states (stop/pause/resume).

    Provides a unified interface for all connectors to:
    - Declare supported states
    - Respond to state change requests
    - Monitor for state transitions
    - Save/restore progress checkpoints
    """

    # Valid state transitions
    VALID_TRANSITIONS = {
        "running": ["stopping", "pausing", "completed", "failed", "stopped"],
        "stopping": ["stopped", "failed"],
        "stopped": [],
        "pausing": ["paused", "failed"],
        "paused": ["resuming", "failed"],
        "resuming": ["running", "failed"],
        "completed": [],
        "failed": [],
    }

    # Default supported states (all connectors can support stop)
    DEFAULT_SUPPORTED_STATES = {
        "stop": True,  # Halt execution
        "pause": False,  # Suspend and save state
        "resume": False,  # Continue from pause
    }

    def __init__(
        self,
        context,
        supported_states: Optional[Dict[str, bool]] = None,
        checkpoint_interval: int = 60,
        signal_check_interval: int = 5,
    ):
        """
        Initialize state manager

        Args:
            context: OpenFaaS context object
            supported_states: Dict of {state: bool} indicating support
            checkpoint_interval: Seconds between checkpoints (default 60)
            signal_check_interval: Seconds between signal checks (default 5)
        """
        self.context = context
        self.supported_states = {**self.DEFAULT_SUPPORTED_STATES, **(supported_states or {})}
        self.checkpoint_interval = checkpoint_interval
        self.signal_check_interval = signal_check_interval

        self.current_state = "running"
        self.requested_state = None
        self.redis_handler = None
        self.control_context = None
        self.last_signal_check = time.time()
        self.last_checkpoint = time.time()
        self._state_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._on_state_change_callbacks = []

    def initialize(self) -> bool:
        """
        Initialize Redis signal monitoring

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Get execution ID
            execution_id = self.context.scan_execution_id
            if not execution_id:
                logger.warning("No execution ID available, signal monitoring disabled")
                return False

            # Initialize Redis handler
            self.redis_handler = RedisSignalHandler()

            if not self.redis_handler.health_check():
                logger.warning("Redis unavailable, signal monitoring disabled")
                return False

            # Create control context
            self.control_context = ScanControlContext(execution_id, self.redis_handler)

            # Update status
            self.redis_handler.update_status(execution_id, "running")

            logger.info(f"State manager initialized (supported_states={self.supported_states})")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize state manager: {e}")
            return False

    def check_for_state_changes(self) -> bool:
        """
        Check for state change requests from Redis

        Returns:
            True if stop was requested, False otherwise
        """
        if not self.control_context:
            return False

        current_time = time.time()
        if current_time - self.last_signal_check < self.signal_check_interval:
            logger.info("check_for_state_changes: too soon")
            return False  # Not time to check yet

        self.last_signal_check = current_time

        # Check for incoming signals
        try:
            # Socket timeout is configured on Redis client prevent indefinite blocking if it becomes unresponsive.
            signal = self.control_context.check_for_signals()
            if signal and self.control_context.stop_requested:
                self.requested_state = "stop"
                # Actually transition to stopping state
                if self.current_state == "running":
                    if self.set_state("stopping"):
                        logger.info("State transitioned (from_state=running, to_state=stopping)")
                return True
        except Exception as e:
            # just return and allow subsequent calls, in case the issue is transient
            logger.warning(f"Error checking state changes: {e}")

        return False

    def should_stop(self) -> bool:
        """
        Check if execution should stop

        Returns:
            True if stop was requested, False otherwise
        """
        self.check_for_state_changes()
        with self._state_lock:
            return self.requested_state == "stop"

    def should_pause(self) -> bool:
        """
        Check if execution should pause

        Returns:
            True if pause was requested and supported, False otherwise
        """
        if not self.supported_states.get("pause", False):
            return False

        self.check_for_state_changes()
        with self._state_lock:
            return (
                self.requested_state == "pause"
                and self.control_context is not None
                and self.control_context.pause_requested
            )

    def should_checkpoint(self) -> bool:
        """
        Check if it's time to save a checkpoint

        Returns:
            True if checkpoint interval has elapsed, False otherwise
        """
        current_time = time.time()
        elapsed = current_time - self.last_checkpoint
        if elapsed >= self.checkpoint_interval:
            return True
        return False

    def save_checkpoint(self, checkpoint_data: Dict[str, Any]) -> Optional[str]:
        """
        Save execution progress checkpoint

        Args:
            checkpoint_data: Dictionary with checkpoint information
                - progress: current progress data
                - timestamp: ISO8601 timestamp
                - additional fields as needed

        Returns:
            Checkpoint ID if successful, None otherwise
        """
        if not self.redis_handler or not self.control_context:
            return None

        try:
            execution_id = self.context.scan_execution_id
            checkpoint_id = self.redis_handler.save_checkpoint(execution_id, checkpoint_data)
            self.last_checkpoint = time.time()

            logger.debug(f"Checkpoint saved (execution_id={execution_id}, checkpoint_id={checkpoint_id})")
            return checkpoint_id

        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
            return None

    def set_state(self, new_state: str) -> bool:
        """
        Transition to a new state

        Args:
            new_state: Target state name

        Returns:
            True if transition is valid and successful, False otherwise
        """
        with self._state_lock:
            valid_transitions = self.VALID_TRANSITIONS.get(self.current_state, [])

            if new_state not in valid_transitions:
                logger.warning(f"Invalid state transition (from_state={self.current_state}, to_state={new_state})")
                return False

            old_state = self.current_state
            self.current_state = new_state

            logger.info(f"State transitioned (from_state={old_state}, to_state={new_state})")

        # Call callbacks outside lock to avoid deadlocks
        self._trigger_state_change_callbacks(old_state, new_state)
        return True

    def on_state_change(self, callback: Callable[[str, str], None]) -> None:
        """
        Register callback for state change events

        Args:
            callback: Function(old_state, new_state) to call on state changes
        """
        self._on_state_change_callbacks.append(callback)

    def _trigger_state_change_callbacks(self, old_state: str, new_state: str):
        """Trigger all registered callbacks for state change"""
        for callback in self._on_state_change_callbacks:
            try:
                callback(old_state, new_state)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")

    def shutdown(self, final_status: str = "stopped") -> bool:
        """
        Gracefully shut down and transition to final state

        Args:
            final_status: Final state ('stopped', 'completed', 'failed')

        Returns:
            True if shutdown successful, False otherwise
        """
        try:
            # Transition state
            if not self.set_state(final_status):
                logger.warning(f"Could not transition to {final_status}")
                return False

            # Update Redis status
            if self.redis_handler:
                execution_id = self.context.scan_execution_id
                self.redis_handler.update_status(
                    execution_id, final_status, "Execution stopped", {"partial_data": final_status == "stopped"}
                )

                # Cleanup streams
                self.redis_handler.cleanup_streams(execution_id)

            self._shutdown_event.set()
            logger.info(f"State manager shutdown with final status: {final_status}")
            return True

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            return False

    def is_shutdown(self) -> bool:
        """Check if shutdown has been initiated"""
        return self._shutdown_event.is_set()

    def supports_state(self, state: str) -> bool:
        """Check if connector supports a state"""
        return self.supported_states.get(state, False)

    def get_supported_states(self) -> Dict[str, bool]:
        """Get all supported states"""
        return self.supported_states.copy()

    def get_current_state(self) -> str:
        """Get current execution state"""
        with self._state_lock:
            return self.current_state

    def close(self):
        """Clean up resources"""
        if self.redis_handler:
            self.redis_handler.close()
