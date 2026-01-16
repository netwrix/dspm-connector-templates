# Stop/Pause/Resume Implementation Guide for Connectors

This guide explains how to implement stop/pause/resume functionality in OpenFaaS connectors using the built-in State Manager framework.

## Overview

The framework provides out-of-the-box support for:
- **Stop**: Gracefully halt execution and preserve partial data
- **Pause**: (Future) Suspend execution and save state
- **Resume**: (Future) Continue from a saved checkpoint

All connectors have stop capability enabled by default. Other states can be opted-in per connector.

## Quick Start

### 1. Initialize State Manager in Handler

In your handler, initialize the StateManager for stop/pause/resume support:

```python
from function.state_manager import StateManager

def handle(event, context):
    """Main handler function"""
    
    # Initialize state manager for this scan/sync operation
    state_manager = StateManager(
        context=context,
        supported_states={'stop': True, 'pause': False, 'resume': False}
    )
    
    # Initialize Redis monitoring (connects to control streams)
    if not state_manager.initialize():
        # Redis unavailable - graceful degradation
        context.log.warning("State management unavailable, continuing without stop capability")
        state_manager = None
    
    return process_scan(state_manager, context)

def process_scan(state_manager, context):
    """Main scanning loop"""
    
    for item in items_to_process:
        # Check for stop signal periodically
        if state_manager and state_manager.should_stop():
            context.log.info("Stop signal received, exiting gracefully")
            state_manager.shutdown('stopped')
            return context.access_scan_success_response()
        
        # Process item...
        process_item(item)
        
        # Optionally save progress checkpoint
        if state_manager and state_manager.should_checkpoint():
            state_manager.save_checkpoint({
                'processed_items': count,
                'last_item': item.id,
                'timestamp': datetime.now(UTC).isoformat()
            })
    
    # Graceful completion
    if state_manager:
        state_manager.shutdown('completed')
    return context.access_scan_success_response()
```

### 2. Declare Supported States (Optional)

Customize which states your connector supports during initialization:

```python
state_manager = StateManager(
    context=context,
    supported_states={
        'stop': True,      # Support graceful termination (default)
        'pause': False,    # Pause not yet supported
        'resume': False    # Resume not yet supported
    }
)
```

## Detailed Reference

### State Manager API

The StateManager class provides the following interface for handlers:

#### Initialization

```python
from function.state_manager import StateManager

state_manager = StateManager(
    context=context,                    # Required: OpenFaaS context
    supported_states={                  # Optional: customize support
        'stop': True,
        'pause': False,
        'resume': False
    },
    checkpoint_interval=60,             # Optional: seconds between checkpoints
    signal_check_interval=5             # Optional: seconds between signal checks
)

# Initialize Redis connection and monitoring
success = state_manager.initialize()
```

#### Checking for State Changes

```python
# Check if stop was requested
if state_manager.should_stop():
    # Halt execution gracefully
    break

# Check if pause was requested (if supported)
if state_manager.should_pause():
    # Save state and suspend
    break

# Check if it's time to save progress
if state_manager.should_checkpoint():
    # Save current progress for resume
    state_manager.save_checkpoint({...})
```

#### Checking State

```python
# Get current state
current = state_manager.get_current_state()  # Returns: 'running', 'stopping', 'stopped', etc.

# Check if shutdown initiated
if state_manager.is_shutdown():
    break
```

#### Saving Progress

```python
checkpoint_id = state_manager.save_checkpoint({
    'objects_processed': 1000,
    'current_path': '/share/folder',
    'failed_items': [],
    'timestamp': datetime.now(UTC).isoformat()
})
```
#### Checkpoint Data

```python
# Checkpoints are automatically saved and trimmed
# The last 10 checkpoints are kept by the framework
# Checkpoints include:
# - timestamp: ISO8601 timestamp when saved
# - state: current scanning state
# - scanned_paths: list of completed paths
# - current_path: path being processed
# - objects_count: number of objects scanned
# - failed_paths: list of failed paths
# - worker_states: individual worker progress
```


#### Shutting Down

```python
# Graceful shutdown with final status
state_manager.shutdown('stopped')   # Halted by stop request
state_manager.shutdown('completed') # Completed successfully
state_manager.shutdown('failed')    # Failed with error
```

#### Checking Capabilities

```python
# Check if a state is supported
if state_manager.supports_state('pause'):
    # Pause is supported
    pass

# Get all supported states
states = state_manager.get_supported_states()
# Returns: {'stop': True, 'pause': False, 'resume': False}
```

### State Transitions

Valid state transitions:
```
running
  ├─ stopping (stop signal received)
  │   └─ stopped (gracefully halted)
  │
  ├─ pausing (pause signal received)
  │   └─ paused (suspended with state saved)
  │       └─ resuming (resume requested)
  │           └─ running (continue from checkpoint)
  │
  └─ completed (finished successfully)
  └─ failed (terminated with error)
```

## Best Practices

### 1. Check for Stop Signals at Natural Points

Good places to check:
- After processing each item/directory
- Before starting a time-consuming operation
- Between batches of work
- In worker threads (periodic checks)

```python
# Good: Check after each directory
for directory in directories:
    if state_manager.should_stop():
        break
    process_directory(directory)

# Avoid: Checking too frequently
for item in items:
    for sub_item in item:
        for sub_sub_item in sub_item:
            if state_manager.should_stop():  # Too granular
                break
```

### 2. Save Checkpoints Strategically

```python
# Checkpoint every minute of processing
if state_manager.should_checkpoint():
    state_manager.save_checkpoint({
        'items_processed': count,
        'current_position': current_index,
        'timestamp': datetime.now(UTC).isoformat()
    })
```

### 3. Handle Graceful Shutdown

Always clean up resources before exit:

```python
try:
    # Main processing loop
    for item in items:
        if state_manager.should_stop():
            break
        process(item)
finally:
    # Cleanup (also called by framework)
    state_manager.shutdown('stopped')
```

### 4. Mark Partial Data

When a stop is requested, the framework automatically marks data as partial:

```python
# Framework automatically sets:
# - status: 'stopped'
# - completed_at: timestamp
# - error_details: includes stop reason

# The metadata shows this is incomplete data:
state_manager.shutdown('stopped')
```

## Error Handling

### Redis Connection Unavailable

If Redis is unavailable, the state manager gracefully degrades:

```python
# state_manager will be initialized but may not connect to Redis
if not state_manager or not state_manager.redis_handler:
    # Continue processing without stop capability
    # Processing will continue until completion or timeout
    pass
```

### Handling Shutdown Failures

```python
# Shutdown is idempotent and safe to call multiple times
if not state_manager.shutdown('stopped'):
    context.log.warning("Shutdown had issues but proceeding")
```

## API Endpoint Usage

Users trigger stop/pause/resume via REST API:

```bash
# Stop a running scan
curl -X POST https://localhost:3001/api/v1/scan-executions/{id}/stop \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"reason": "User requested"}'

# Response: 202 Accepted (async operation)
```

## Example: CIFS Connector

```python
from function.state_manager import StateManager

def handle(event, context):
    """CIFS access scan handler"""
    
    # Initialize state manager for stop support
    state_manager = StateManager(
        context=context,
        supported_states={'stop': True}
    )
    
    # Enable Redis monitoring for stop signals
    if not state_manager.initialize():
        context.log.warning("State management unavailable, no stop capability")
        state_manager = None
    
    try:
        # Main scanning loop
        for share in shares:
            # Check for stop signal
            if state_manager and state_manager.should_stop():
                context.log.info("Stop requested, exiting scan")
                break
            
            # Scan share...
            scan_share(share)
            
            # Checkpoint progress every minute
            if state_manager and state_manager.should_checkpoint():
                state_manager.save_checkpoint({
                    'shares_completed': completed_count,
                    'total_shares': len(shares),
                    'current_share': share.name
                })
        
        # Shutdown with appropriate status
        if state_manager:
            final_status = 'stopped' if state_manager.should_stop() else 'completed'
            state_manager.shutdown(final_status)
        
    except Exception as e:
        context.log.error(f"Scan failed: {e}")
        if state_manager:
            state_manager.shutdown('failed')
        raise
    
    return context.access_scan_success_response()
```

## Testing

### Unit Testing State Manager

```python
from function.state_manager import StateManager

def test_state_transitions():
    """Test state transitions"""
    manager = StateManager(context_mock)
    
    # Test stop signal
    assert manager.get_current_state() == 'running'
    manager.set_state('stopping')
    assert manager.get_current_state() == 'stopping'
    manager.set_state('stopped')
    assert manager.get_current_state() == 'stopped'

def test_checkpoint():
    """Test checkpoint save/retrieve"""
    manager = StateManager(context_mock)
    manager.initialize()
    
    checkpoint_data = {'objects_count': 50, 'progress': 50}
    checkpoint_id = manager.save_checkpoint(checkpoint_data)
    
    # Checkpoint saved successfully
    assert checkpoint_id is not None
```

### Integration Testing

```python
def test_stop_during_scan():
    """Integration test: stop signal during scan"""
    # Simulate stop signal in Redis
    redis.xadd('scan:control:{id}', {'action': 'STOP'})
    
    # Run scan
    response = handle(event, context)
    
    # Verify scan stopped
    execution = ScanExecution.find(id)
    assert execution.status == 'stopped'
    assert execution.is_partial == True
```

## Troubleshooting

### State Manager Initialization Failed

```
Issue: state_manager.initialize() returns False
Reason: Redis connection unavailable or not configured
Solution:
1. Verify REDIS_URL environment variable is set
2. Ensure Redis service is running and accessible
3. Check network connectivity to Redis host
4. Handler should gracefully degrade when Redis unavailable
```

### Stop Signal Not Received

```
Issue: Stop signal not being detected
Reason: Check interval is 5 seconds by default
Solution: Increase frequency of should_stop() calls
```

### Redis Connection Failed

```
Issue: Checkpoint save/restore not working
Reason: Redis unavailable
Solution: Verify REDIS_URL environment variable and Redis accessibility
```

## Migration from Manual Stop Handling

If you have existing stop handling code:

### Before (Manual):
```python
def handle(event, context):
    stop_signal = check_redis_for_stop()  # Manual check
    while not stop_signal:
        process_item()
        stop_signal = check_redis_for_stop()
```

### After (Framework):
```python
from function.state_manager import StateManager

def handle(event, context):
    # Initialize state manager in your handler
    state_manager = StateManager(context=context)
    if not state_manager.initialize():
        state_manager = None
    
    while True:
        if state_manager and state_manager.should_stop():
            break
        process_item()
    
    if state_manager:
        state_manager.shutdown('completed')
```

## Future: Pause/Resume

The framework is designed to support pause/resume in the future:

```python
# When pause/resume are enabled (future):
if state_manager.should_pause():
    state_manager.save_checkpoint({...})
    state_manager.shutdown('paused')

# On resume (future):
# Checkpoints are stored in Redis Streams
# Last 10 checkpoints are available via Redis directly
# Handler can retrieve checkpoint data from Redis if needed
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review [`redis_signal_handler.py`](../connectors/source/cifs/access-scan/redis_signal_handler.py) for implementation details
3. Check Core API logs for stop signal events
