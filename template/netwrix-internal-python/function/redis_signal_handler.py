#!/usr/bin/env python3
"""
Redis Signal Handler for graceful stop/pause/resume functionality
Monitors Redis Streams for control signals from the Core API
"""

import redis
import json
import os
import time
from datetime import datetime
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class RedisSignalHandler:
    """Handle control signals from Redis Streams for scan execution management"""

    CONTROL_STREAM_TTL = 86400  # 24 hours

    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize Redis connection for signal handling

        Args:
            redis_url: Redis connection URL (default from environment)
        """
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379")
        self.client = None
        self._connect()

    def _connect(self) -> None:
        """
        Establish connection to Redis
        """
        try:
            # Add socket timeout to prevent hangs
            # Note: socket_keepalive_options removed as it causes "Invalid argument" errors on some platforms
            self.client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,  # 2 second connection timeout
                socket_timeout=2,  # 2 second read/write timeout
                socket_keepalive=True,  # Enable keepalive without custom options
            )
            self.client.ping()
            logger.info(f"Connected to Redis for signal handling (redis_url={self.redis_url})")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)} (redis_url={self.redis_url})")
            self.client = None

    def check_control_signal(self, execution_id: str, last_message_id: str = "0") -> Optional[Dict[str, Any]]:
        """
        Check for control signals (STOP, PAUSE, RESUME)
        Non-blocking read from Redis Stream

        Args:
            execution_id: The scan execution ID
            last_message_id: The last message ID read (for stream continuation)

        Returns:
            Dict with signal data or None if no signal or error
        """
        try:
            control_stream_key = f"scan:control:{execution_id}"

            # Non-blocking read: read latest message after last_message_id
            # Socket timeout is already configured on the Redis client (2 seconds)
            messages = self.client.xread(
                {control_stream_key: last_message_id},
                count=1,
                block=0,
            )

            if not messages or len(messages) == 0:
                return None

            # Extract message data
            stream_key, stream_messages = messages[0]
            if not stream_messages:
                return None

            message_id, data = stream_messages[0]

            # Include the message ID for tracking
            data["_id"] = message_id

            logger.info(
                f"Control signal received (execution_id={execution_id}, action={data.get('action')}, message_id={message_id})"
            )

            return data

        except redis.exceptions.RedisError as e:
            # Attempt to reconnect on Redis errors
            logger.warning(f"Redis error reading control signal (execution_id={execution_id}, error={str(e)})")
            self._connect()
            return None
        except Exception as e:
            # Log other errors at debug level since some are expected (e.g., timeouts)
            logger.debug(f"Error reading control signal (execution_id={execution_id}, error={str(e)})")
            return None

    def save_checkpoint(self, execution_id: str, checkpoint_data: Dict[str, Any]) -> Optional[str]:
        """
        Save checkpoint for pause/resume functionality

        Args:
            execution_id: The scan execution ID
            checkpoint_data: Dictionary containing checkpoint data
                - state: current scanning state
                - share: current share being scanned
                - shares_scanned: list of completed share names
                - shares_failed: list of failed share names
                - complete_dirs: list of completed dirs in the current share
                - failed_dirs: list of failed dirs in the current share

        Returns:
            Message ID if successful, None otherwise
        """
        try:
            checkpoint_stream_key = f"scan:checkpoint:{execution_id}"

            message_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "state": checkpoint_data.get("state", ""),
                "share": checkpoint_data.get("share", ""),
                "shares_scanned": json.dumps(list(checkpoint_data.get("shares_scanned", []))),
                "shares_failed": json.dumps(list(checkpoint_data.get("shares_failed", []))),
                "complete_dirs": json.dumps(list(checkpoint_data.get("complete_dirs", []))),
                "failed_dirs": json.dumps(list(checkpoint_data.get("failed_dirs", []))),
            }

            message_id = self.client.xadd(checkpoint_stream_key, message_data)

            # Set expiration
            self.client.expire(checkpoint_stream_key, self.CONTROL_STREAM_TTL)

            # Trim to keep only last 10 checkpoints
            self.client.xtrim(checkpoint_stream_key, maxlen=10, approximate=True)

            logger.debug(
                f"Checkpoint saved (execution_id={execution_id}, message_id={message_id}, objects_count={checkpoint_data.get('objects_count')})"
            )

            return message_id

        except redis.exceptions.RedisError as e:
            # Attempt to reconnect on Redis errors
            logger.warning(f"Redis error saving checkpoint (execution_id={execution_id}, error={str(e)})")
            self._connect()
            return None
        except Exception as e:
            logger.warning(f"Failed to save checkpoint (execution_id={execution_id}, error={str(e)})")
            return None

    def update_status(
        self, execution_id: str, status: str, message: str = "", metadata: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Update status in Redis Stream for monitoring

        Args:
            execution_id: The scan execution ID
            status: Current status (stopping, stopped, etc.)
            message: Optional status message
            metadata: Optional metadata dict

        Returns:
            Message ID if successful, None otherwise
        """
        try:
            status_stream_key = f"scan:status:{execution_id}"

            metadata = metadata or {}
            message_data = {
                "status": status,
                "timestamp": datetime.utcnow().isoformat(),
                "message": message,
                "partial_data": str(metadata.get("partial_data", False)).lower(),
                "objects_count": str(metadata.get("objects_count", 0)),
                "failed_paths_count": str(metadata.get("failed_paths_count", 0)),
            }

            message_id = self.client.xadd(status_stream_key, message_data)

            # Set expiration
            self.client.expire(status_stream_key, self.CONTROL_STREAM_TTL)

            # Trim to keep only last 100 status updates
            self.client.xtrim(status_stream_key, maxlen=100, approximate=True)

            logger.info(f"Status updated (execution_id={execution_id}, status={status})")

            return message_id

        except redis.exceptions.RedisError as e:
            # Attempt to reconnect on Redis errors
            logger.warning(
                f"Redis error updating status (execution_id={execution_id}, status={status}, error={str(e)})"
            )
            self._connect()
            return None
        except Exception as e:
            logger.warning(f"Failed to update status (execution_id={execution_id}, status={status}, error={str(e)})")
            return None

    def cleanup_streams(self, execution_id: str) -> bool:
        """
        Clean up all streams for a scan execution
        Should be called when scan is complete

        Args:
            execution_id: The scan execution ID

        Returns:
            True if successful, False otherwise
        """
        keys_to_delete = [
            f"scan:control:{execution_id}",
            f"scan:checkpoint:{execution_id}",
            f"scan:status:{execution_id}",
        ]

        try:
            deleted = self.client.delete(*keys_to_delete)
            logger.info(f"Streams cleaned up (execution_id={execution_id}, keys_deleted={deleted})")
            return deleted > 0

        except redis.exceptions.RedisError as e:
            # Attempt to reconnect and retry cleanup on Redis errors
            logger.warning(
                f"Redis error during cleanup, attempting reconnect (execution_id={execution_id}, error={str(e)})"
            )
            self._connect()
            try:
                deleted = self.client.delete(*keys_to_delete)
                logger.info(f"Streams cleaned up after reconnect (execution_id={execution_id}, keys_deleted={deleted})")
                return deleted > 0
            except Exception as retry_e:
                logger.warning(
                    f"Failed to cleanup streams after reconnect (execution_id={execution_id}, error={str(retry_e)})"
                )
                return False
        except Exception as e:
            logger.warning(f"Failed to cleanup streams (execution_id={execution_id}, error={str(e)})")
            return False

    def health_check(self) -> bool:
        """
        Check if Redis connection is healthy

        Returns:
            True if Redis is accessible, False otherwise
        """
        try:
            self.client.ping()
            return True
        except redis.exceptions.RedisError:
            # Attempt to reconnect on Redis errors
            self._connect()

        try:
            self.client.ping()
            return True
        except Exception as e:
            logger.warning(f"Redis health check failed: {str(e)}")
            return False

    def close(self):
        """Close Redis connection"""
        if self.client:
            try:
                self.client.close()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {str(e)}")
            finally:
                self.client = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class ScanControlContext:
    """
    Context for managing scan control state
    Tracks stop signals and checkpoint intervals
    """

    def __init__(self, execution_id: str, redis_handler: RedisSignalHandler):
        """
        Initialize scan control context

        Args:
            execution_id: The scan execution ID
            redis_handler: Redis signal handler instance
        """
        self.execution_id = execution_id
        self.redis_handler = redis_handler
        self.stop_requested = False
        self.pause_requested = False
        self.last_signal_id = "0"
        self.last_checkpoint_time = time.time()
        self.checkpoint_interval = 60  # seconds

    def check_for_signals(self) -> bool:
        """
        Check for control signals

        Returns:
            True if stop signal received, False otherwise
        """
        signal = self.redis_handler.check_control_signal(self.execution_id, self.last_signal_id)

        if signal:
            self.last_signal_id = signal.get("_id", self.last_signal_id)
            action = signal.get("action")

            if action == "STOP":
                self.stop_requested = True
                logger.info(f"Stop signal received (execution_id={self.execution_id})")
                return True
            elif action == "PAUSE":
                self.pause_requested = True
                logger.info(f"Pause signal received (execution_id={self.execution_id})")
            elif action == "RESUME":
                self.pause_requested = False
                logger.info(f"Resume signal received (execution_id={self.execution_id})")

        return self.stop_requested

    def should_checkpoint(self) -> bool:
        """
        Check if it's time to save a checkpoint

        Returns:
            True if checkpoint interval has elapsed, False otherwise
        """
        elapsed = time.time() - self.last_checkpoint_time
        return elapsed >= self.checkpoint_interval

    def update_checkpoint_time(self):
        """Update the last checkpoint timestamp"""
        self.last_checkpoint_time = time.time()

    def should_stop(self) -> bool:
        """
        Check if scanning should stop

        Returns:
            True if stop was requested, False otherwise
        """
        return self.stop_requested

    def should_pause(self) -> bool:
        """
        Check if scanning should pause

        Returns:
            True if pause was requested, False otherwise
        """
        return self.pause_requested
