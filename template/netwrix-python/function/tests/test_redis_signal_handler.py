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
import json
import time
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime

# Import the module to test
from function.redis_signal_handler import (
    RedisSignalHandler,
    ScanControlContext,
    TimeoutError,
    run_with_timeout
)


class TestRunWithTimeout:
    """Test the run_with_timeout utility function"""
    
    def test_run_with_timeout_success(self):
        """Test function completes within timeout"""
        def quick_func(x, y):
            return x + y
        
        result = run_with_timeout(
            quick_func,
            args=(5, 3),
            timeout=5
        )
        assert result == 8
    
    def test_run_with_timeout_timeout(self):
        """Test function times out"""
        def slow_func():
            time.sleep(2)
            return "should not reach"
        
        with pytest.raises(TimeoutError):
            run_with_timeout(slow_func, timeout=0.5)
    
    def test_run_with_timeout_with_kwargs(self):
        """Test function with keyword arguments"""
        def func_with_kwargs(a, b=10):
            return a * b
        
        result = run_with_timeout(
            func_with_kwargs,
            args=(3,),
            kwargs={'b': 5},
            timeout=5
        )
        assert result == 15


class TestRedisSignalHandler:
    """Test RedisSignalHandler class"""
    
    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client"""
        return MagicMock()
    
    @pytest.fixture
    def handler(self, mock_redis_client):
        """Create RedisSignalHandler with mocked Redis"""
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler('redis://localhost:6379')
            return handler
    
    def test_initialization_success(self, mock_redis_client):
        """Test successful Redis connection"""
        mock_redis_client.ping.return_value = True
        
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            handler = RedisSignalHandler('redis://localhost:6379')
        
        assert handler.connected is True
        assert handler.client is not None
        assert handler.redis_url == 'redis://localhost:6379'
    
    def test_initialization_failure(self):
        """Test failed Redis connection"""
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.side_effect = Exception("Connection refused")
            handler = RedisSignalHandler('redis://localhost:6379')
        
        assert handler.connected is False
        assert handler.client is None
    
    def test_check_control_signal_success(self, handler, mock_redis_client):
        """Test successful control signal reading"""
        handler.connected = True
        handler.client = mock_redis_client
        
        # Mock xread response
        mock_redis_client.xread.return_value = [
            ('scan:control:exec-123', [
                ('1234567890-0', {'action': 'STOP', 'reason': 'user_request'})
            ])
        ]
        
        with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
            mock_timeout.return_value = [
                ('scan:control:exec-123', [
                    ('1234567890-0', {'action': 'STOP', 'reason': 'user_request'})
                ])
            ]
            signal = handler.check_control_signal('exec-123', '0')
        
        assert signal is not None
        assert signal['action'] == 'STOP'
        assert signal['_id'] == '1234567890-0'
    
    def test_check_control_signal_no_signal(self, handler, mock_redis_client):
        """Test no control signal available"""
        handler.connected = True
        handler.client = mock_redis_client
        
        with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
            mock_timeout.return_value = []
            signal = handler.check_control_signal('exec-123', '0')
        
        assert signal is None
    
    def test_check_control_signal_timeout(self, handler, mock_redis_client):
        """Test timeout when reading control signal"""
        handler.connected = True
        handler.client = mock_redis_client
        
        with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
            mock_timeout.side_effect = TimeoutError("Timeout")
            signal = handler.check_control_signal('exec-123', '0')
        
        assert signal is None
        assert handler.connected is False
    
    def test_save_checkpoint_success(self, handler, mock_redis_client):
        """Test successful checkpoint saving"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = '1234567890-1'
        
        checkpoint_data = {
            'state': {'processing': 10},
            'scanned_paths': ['/path1', '/path2'],
            'current_path': '/path1',
            'objects_count': 100,
            'failed_paths': [],
            'worker_states': {}
        }
        
        result = handler.save_checkpoint('exec-123', checkpoint_data)
        
        assert result == '1234567890-1'
        mock_redis_client.xadd.assert_called_once()
        mock_redis_client.expire.assert_called_once_with('scan:checkpoint:exec-123', 86400)
    
    def test_save_checkpoint_failure(self, handler, mock_redis_client):
        """Test checkpoint save failure"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.xadd.side_effect = Exception("Redis error")
        
        result = handler.save_checkpoint('exec-123', {})
        
        assert result is None
    
    def test_update_status_success(self, handler, mock_redis_client):
        """Test successful status update"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.xadd.return_value = '1234567890-2'
        
        result = handler.update_status(
            'exec-123',
            'stopping',
            'Stop signal received',
            {'partial_data': True, 'objects_count': 50}
        )
        
        assert result == '1234567890-2'
        mock_redis_client.xadd.assert_called_once()
        args, kwargs = mock_redis_client.xadd.call_args
        message_data = args[1]
        assert message_data['status'] == 'stopping'
    
    def test_cleanup_streams_success(self, handler, mock_redis_client):
        """Test successful stream cleanup"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.delete.return_value = 3
        
        result = handler.cleanup_streams('exec-123')
        
        assert result is True
        mock_redis_client.delete.assert_called_once()
        # Verify all three streams are targeted
        call_args = mock_redis_client.delete.call_args[0]
        assert 'scan:control:exec-123' in call_args
        assert 'scan:checkpoint:exec-123' in call_args
        assert 'scan:status:exec-123' in call_args
    
    def test_cleanup_streams_failure(self, handler, mock_redis_client):
        """Test stream cleanup failure"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.delete.side_effect = Exception("Redis error")
        
        result = handler.cleanup_streams('exec-123')
        
        assert result is False
    
    def test_health_check_success(self, handler, mock_redis_client):
        """Test successful health check"""
        handler.connected = True
        handler.client = mock_redis_client
        
        with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
            mock_timeout.return_value = True
            result = handler.health_check()
        
        assert result is True
    
    def test_health_check_timeout(self, handler, mock_redis_client):
        """Test health check with timeout"""
        handler.connected = True
        handler.client = mock_redis_client
        
        with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
            mock_timeout.side_effect = TimeoutError("Timeout")
            result = handler.health_check()
        
        assert result is False
        assert handler.connected is False
    
    def test_close(self, handler, mock_redis_client):
        """Test closing Redis connection"""
        handler.connected = True
        handler.client = mock_redis_client
        
        handler.close()
        
        mock_redis_client.close.assert_called_once()
        assert handler.connected is False
        assert handler.client is None
    
    def test_close_with_error(self, handler, mock_redis_client):
        """Test closing Redis connection with error"""
        handler.connected = True
        handler.client = mock_redis_client
        mock_redis_client.close.side_effect = Exception("Close error")
        
        # Should not raise exception
        handler.close()
        
        assert handler.client is None
        assert handler.connected is False
    
    def test_context_manager(self, mock_redis_client):
        """Test using RedisSignalHandler as context manager"""
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_redis_client
            
            with RedisSignalHandler('redis://localhost:6379') as handler:
                assert handler.connected is True
            
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
        return ScanControlContext('exec-123', mock_handler)
    
    def test_initialization(self, context):
        """Test ScanControlContext initialization"""
        assert context.execution_id == 'exec-123'
        assert context.stop_requested is False
        assert context.pause_requested is False
        assert context.last_signal_id == '0'
    
    def test_check_for_signals_stop(self, context, mock_handler):
        """Test checking for STOP signal"""
        mock_handler.check_control_signal.return_value = {
            'action': 'STOP',
            '_id': '123-0'
        }
        
        result = context.check_for_signals()
        
        assert result is True
        assert context.stop_requested is True
        assert context.last_signal_id == '123-0'
    
    def test_check_for_signals_pause(self, context, mock_handler):
        """Test checking for PAUSE signal"""
        mock_handler.check_control_signal.return_value = {
            'action': 'PAUSE',
            '_id': '123-0'
        }
        
        result = context.check_for_signals()
        
        assert result is False  # Not a stop request
        assert context.pause_requested is True
    
    def test_check_for_signals_resume(self, context, mock_handler):
        """Test checking for RESUME signal"""
        context.pause_requested = True
        mock_handler.check_control_signal.return_value = {
            'action': 'RESUME',
            '_id': '123-0'
        }
        
        result = context.check_for_signals()
        
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


class TestTimeoutHandling:
    """Test timeout handling in signal operations"""
    
    def test_xread_timeout_reconnection(self):
        """Test that connection is marked as broken on timeout"""
        mock_client = MagicMock()
        
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_client
            handler = RedisSignalHandler('redis://localhost:6379')
            handler.connected = True
            
            with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
                mock_timeout.side_effect = TimeoutError("xread timeout")
                signal = handler.check_control_signal('exec-123')
            
            assert handler.connected is False
            assert signal is None
    
    def test_ping_timeout_reconnection(self):
        """Test that ping timeout marks connection as broken"""
        mock_client = MagicMock()
        
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_client
            handler = RedisSignalHandler('redis://localhost:6379')
            handler.connected = True
            
            with patch('function.redis_signal_handler.run_with_timeout') as mock_timeout:
                mock_timeout.side_effect = TimeoutError("ping timeout")
                result = handler.health_check()
            
            assert result is False
            assert handler.connected is False


class TestStreamTrimming:
    """Test stream trimming functionality"""
    
    def test_checkpoint_stream_trim(self):
        """Test checkpoint stream is trimmed to max 10 items"""
        mock_client = MagicMock()
        
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_client
            handler = RedisSignalHandler('redis://localhost:6379')
            handler.connected = True
            handler.client = mock_client
            
            handler.save_checkpoint('exec-123', {})
            
            # Verify xtrim was called with correct parameters
            xtrim_calls = mock_client.xtrim.call_args_list
            assert len(xtrim_calls) > 0
            call_args = xtrim_calls[0]
            assert call_args[0][0] == 'scan:checkpoint:exec-123'
            assert call_args[1].get('maxlen') == 10
            assert call_args[1].get('approximate') is True
    
    def test_status_stream_trim(self):
        """Test status stream is trimmed to max 100 items"""
        mock_client = MagicMock()
        
        with patch('function.redis_signal_handler.redis.from_url') as mock_from_url:
            mock_from_url.return_value = mock_client
            handler = RedisSignalHandler('redis://localhost:6379')
            handler.connected = True
            handler.client = mock_client
            
            handler.update_status('exec-123', 'running')
            
            xtrim_calls = mock_client.xtrim.call_args_list
            assert len(xtrim_calls) > 0
            call_args = xtrim_calls[0]
            assert call_args[0][0] == 'scan:status:exec-123'
            assert call_args[1].get('maxlen') == 100
