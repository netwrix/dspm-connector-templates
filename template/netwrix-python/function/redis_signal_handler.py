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
    STREAM_CHECK_INTERVAL = 5  # seconds between checks
    
    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize Redis connection for signal handling
        
        Args:
            redis_url: Redis connection URL (default from environment)
        """
        self.redis_url = redis_url or os.environ.get('REDIS_URL', 'redis://localhost:6379')
        self.client = None
        self.connected = False
        self._connect()

    def _connect(self) -> bool:
        """
        Establish connection to Redis
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.client = redis.from_url(self.redis_url, decode_responses=True)
            self.client.ping()
            self.connected = True
            logger.info("Connected to Redis for signal handling", redis_url=self.redis_url)
            return True
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e), redis_url=self.redis_url)
            self.connected = False
            return False

    def check_control_signal(
        self, execution_id: str, last_message_id: str = "0"
    ) -> Optional[Dict[str, Any]]:
        """
        Check for control signals (STOP, PAUSE, RESUME)
        Non-blocking read from Redis Stream
        
        Args:
            execution_id: The scan execution ID
            last_message_id: The last message ID read (for stream continuation)
        
        Returns:
            Dict with signal data or None if no signal or error
        """
        if not self.connected:
            if not self._connect():
                return None

        try:
            control_stream_key = f"scan:control:{execution_id}"
            
            # Non-blocking read: read latest message after last_message_id
            messages = self.client.xread(
                {control_stream_key: last_message_id},
                count=1,
                block=0  # Non-blocking
            )

            if not messages or len(messages) == 0:
                return None

            # Extract message data
            stream_key, stream_messages = messages[0]
            if not stream_messages:
                return None

            message_id, data = stream_messages[0]
            
            # Include the message ID for tracking
            data['_id'] = message_id
            
            logger.info(
                "Control signal received",
                execution_id=execution_id,
                action=data.get('action'),
                message_id=message_id
            )
            
            return data

        except Exception as e:
            logger.warning(
                "Error reading control signal",
                execution_id=execution_id,
                error=str(e)
            )
            return None

    def save_checkpoint(
        self, execution_id: str, checkpoint_data: Dict[str, Any]
    ) -> Optional[str]:
        """
        Save checkpoint for pause/resume functionality
        
        Args:
            execution_id: The scan execution ID
            checkpoint_data: Dictionary containing checkpoint data
                - state: current scanning state
                - scanned_paths: set of completed paths
                - current_path: path being processed
                - objects_count: number of objects scanned
                - failed_paths: list of failed paths
                - worker_states: individual worker progress
        
        Returns:
            Message ID if successful, None otherwise
        """
        if not self.connected:
            if not self._connect():
                return None

        try:
            checkpoint_stream_key = f"scan:checkpoint:{execution_id}"
            
            message_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'state': json.dumps(checkpoint_data.get('state', {})),
                'scanned_paths': json.dumps(list(checkpoint_data.get('scanned_paths', []))),
                'current_path': checkpoint_data.get('current_path', ''),
                'objects_count': str(checkpoint_data.get('objects_count', 0)),
                'failed_paths': json.dumps(checkpoint_data.get('failed_paths', [])),
                'worker_states': json.dumps(checkpoint_data.get('worker_states', {}))
            }
            
            message_id = self.client.xadd(checkpoint_stream_key, message_data)
            
            # Set expiration
            self.client.expire(checkpoint_stream_key, self.CONTROL_STREAM_TTL)
            
            # Trim to keep only last 10 checkpoints
            self.client.xtrim(checkpoint_stream_key, 'MAXLEN', '~', 10)
            
            logger.debug(
                "Checkpoint saved",
                execution_id=execution_id,
                message_id=message_id,
                objects_count=checkpoint_data.get('objects_count')
            )
            
            return message_id

        except Exception as e:
            logger.warning(
                "Failed to save checkpoint",
                execution_id=execution_id,
                error=str(e)
            )
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
        if not self.connected:
            if not self._connect():
                return None

        try:
            status_stream_key = f"scan:status:{execution_id}"
            
            metadata = metadata or {}
            message_data = {
                'status': status,
                'timestamp': datetime.utcnow().isoformat(),
                'message': message,
                'partial_data': str(metadata.get('partial_data', False)).lower(),
                'objects_count': str(metadata.get('objects_count', 0)),
                'failed_paths_count': str(metadata.get('failed_paths_count', 0))
            }
            
            message_id = self.client.xadd(status_stream_key, message_data)
            
            # Set expiration
            self.client.expire(status_stream_key, self.CONTROL_STREAM_TTL)
            
            # Trim to keep only last 100 status updates
            self.client.xtrim(status_stream_key, 'MAXLEN', '~', 100)
            
            logger.info(
                "Status updated",
                execution_id=execution_id,
                status=status
            )
            
            return message_id

        except Exception as e:
            logger.warning(
                "Failed to update status",
                execution_id=execution_id,
                status=status,
                error=str(e)
            )
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
        if not self.connected:
            return False

        try:
            keys_to_delete = [
                f"scan:control:{execution_id}",
                f"scan:checkpoint:{execution_id}",
                f"scan:status:{execution_id}"
            ]
            
            deleted = self.client.delete(*keys_to_delete)
            
            logger.info(
                "Streams cleaned up",
                execution_id=execution_id,
                keys_deleted=deleted
            )
            
            return deleted > 0

        except Exception as e:
            logger.warning(
                "Failed to cleanup streams",
                execution_id=execution_id,
                error=str(e)
            )
            return False

    def health_check(self) -> bool:
        """
        Check if Redis connection is healthy
        
        Returns:
            True if Redis is accessible, False otherwise
        """
        if not self.connected:
            return self._connect()

        try:
            self.client.ping()
            return True
        except Exception as e:
            logger.warning("Redis health check failed", error=str(e))
            self.connected = False
            return False

    def close(self):
        """Close Redis connection"""
        if self.client:
            try:
                self.client.close()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.warning("Error closing Redis connection", error=str(e))
            finally:
                self.client = None
                self.connected = False

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
        signal = self.redis_handler.check_control_signal(
            self.execution_id,
            self.last_signal_id
        )
        
        if signal:
            self.last_signal_id = signal.get('_id', self.last_signal_id)
            action = signal.get('action')
            
            if action == 'STOP':
                self.stop_requested = True
                logger.info("Stop signal received", execution_id=self.execution_id)
                return True
            elif action == 'PAUSE':
                self.pause_requested = True
                logger.info("Pause signal received", execution_id=self.execution_id)
            elif action == 'RESUME':
                self.pause_requested = False
                logger.info("Resume signal received", execution_id=self.execution_id)
        
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
