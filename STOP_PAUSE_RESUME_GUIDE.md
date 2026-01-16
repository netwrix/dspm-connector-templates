# Stop/Pause/Resume Implementation Guide for Connectors

This guide explains how to implement stop/pause/resume functionality in OpenFaaS connectors using the built-in State Manager framework.

## Overview

The framework provides out-of-the-box support for:
- **Stop**: Gracefully halt execution and preserve partial data
- **Pause**: (Future) Suspend execution and save state
- **Resume**: (Future) Continue from a saved checkpoint

All connectors have stop capability enabled by default. Other states can be opted-in per connector.

## Quick Start

### 1. Declare Supported States (Optional)

In your handler initialization or in the request, specify which states your connector supports:

```python
# In your handler function or __init__:
def get_supported_states():
    """Declare which operations this connector supports"""
    return {
        'stop': True,      # Support graceful termination (default)
        'pause': True,     # Support pause (optional)
        'resume': True,    # Support resume (optional)
    }
```

### 2. Monitor for State Changes

In your main scanning loop:

```python
def handle(event, context):
    """Main handler function"""
    
    # The Context object already has a state_manager initialized by the framework
    # for scan and sync operations. Access it via context.state_manager
    
    state_manager = context.state_manager
    if not state_manager:
        return context.error_response(False, "State management unavailable")
    
    for item in items_to_process:
        # Check for stop/pause signals periodically
        if state_manager.should_stop():
            context.log.info("Stop signal received, exiting gracefully")
            state_manager.shutdown('stopped')
            return context.access_scan_success_response()
        
        # Process item...
        process_item(item)
        
        # Optionally save progress checkpoint (for future resume)
        if state_manager.should_checkpoint():
            state_manager.save_checkpoint({
                'progress': {
                    'processed_items': count,
                    'last_item': item.id
                },
                'timestamp': datetime.now(UTC).isoformat()
            })
    
    # Graceful completion
    state_manager.shutdown('completed')
    return context.access_scan_success_response()
```

## Detailed Reference

### State Manager Interface

#### Checking for State Changes

```python
# Check if stop was requested
if state_manager.should_stop():
    # Halt execution gracefully
    break

# Check if pause was requested
if state_manager.should_pause():
    # Save state and suspend
    break

# Check if it's time to save progress
if state_manager.should_checkpoint():
    # Save current progress for resume
    state_manager.save_checkpoint({...})
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
def handle(event, context):
    """CIFS access scan handler"""
    state_manager = context.state_manager
    
    try:
        # Main scanning loop
        for share in shares:
            if state_manager.should_stop():
                context.log.info("Stop requested, exiting scan")
                break
            
            # Scan share...
            scan_share(share)
            
            # Checkpoint progress every minute
            if state_manager.should_checkpoint():
                state_manager.save_checkpoint({
                    'shares_completed': completed_count,
                    'total_shares': len(shares),
                    'current_share': share.name
                })
        
        # Shutdown with appropriate status
        final_status = 'stopped' if state_manager.should_stop() else 'completed'
        state_manager.shutdown(final_status)
        
    except Exception as e:
        context.log.error(f"Scan failed: {e}")
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

### State Manager Not Initialized

```
Issue: context.state_manager is None
Reason: State manager only initializes for scan/sync operations
Solution: Check that function_type is 'access-scan' or 'sync'
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
def handle(event, context):
    state_manager = context.state_manager
    while True:
        if state_manager.should_stop():
            break
        process_item()
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
