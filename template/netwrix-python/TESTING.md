# Testing Guide - State Manager & Redis Signal Handler

Quick reference for running tests for the Stop/Pause/Resume functionality.

## Prerequisites

Ensure you have pytest installed:
```bash
pip install pytest pytest-cov
```

## Quick Start: Run All Tests

From the `dspm-connector-templates/template/netwrix-python/` directory:

```bash
# Run all tests with verbose output
pytest function/tests/ -v

# Run tests with short output
pytest function/tests/
```

**Expected output:** All 70+ tests should pass ✅

## Test Files

- `function/tests/test_redis_signal_handler.py` - 40+ tests for Redis signal handling
- `function/tests/test_state_manager.py` - 30+ tests for state management

## Common Test Commands

### Run All Tests
```bash
pytest function/tests/ -v
```

### Run Specific Test File
```bash
pytest function/tests/test_redis_signal_handler.py -v
pytest function/tests/test_state_manager.py -v
```

### Run Specific Test Class
```bash
pytest function/tests/test_redis_signal_handler.py::TestRedisSignalHandler -v
pytest function/tests/test_state_manager.py::TestStateManagerInitialization -v
```

### Run Specific Test
```bash
pytest function/tests/test_redis_signal_handler.py::TestRedisSignalHandler::test_initialization_success -v
```

### Run with Coverage Report
```bash
pytest function/tests/ -v --cov=function --cov-report=html
# Open htmlcov/index.html in browser to see coverage report
```

### Run with Short Summary
```bash
pytest function/tests/ -v --tb=short
```

### Run and Stop on First Failure
```bash
pytest function/tests/ -v -x
```

### Run Tests by Marker (if using markers)
```bash
pytest function/tests/ -v -m "unit"
pytest function/tests/ -v -m "redis"
```

## Test Organization

### test_redis_signal_handler.py
- `TestRunWithTimeout` - Timeout utility function tests
- `TestRedisSignalHandler` - Redis connection and operations
- `TestScanControlContext` - Control signal management
- `TestTimeoutHandling` - Timeout edge cases
- `TestStreamTrimming` - Stream management

### test_state_manager.py
- `TestStateManagerInitialization` - Initialization logic
- `TestStateTransitions` - State machine transitions
- `TestSignalChecking` - Signal detection
- `TestCheckpointManagement` - Checkpoint operations
- `TestShutdown` - Shutdown operations
- `TestCallbackManagement` - State change callbacks
- `TestStateManagerClose` - Resource cleanup
- `TestShouldStop` - Stop detection
- `TestShouldPause` - Pause detection

## What Tests Cover

✅ Redis connection management  
✅ Signal reading with timeouts  
✅ Checkpoint save/restore  
✅ Status updates  
✅ Stream cleanup  
✅ Health checks  
✅ State transitions  
✅ Signal checking  
✅ Error handling  
✅ Graceful degradation  
✅ Thread safety  
✅ Timeout scenarios  

## Interpreting Results

### All Tests Pass ✅
```
====== 70 passed in 2.15s ======
```
Great! You're ready to merge.

### Test Failures ❌
Each failure will show:
- Test name
- Error message
- Assertion details
- Traceback

Review the error and the test code to understand what failed.

### Warnings
Some warnings are expected (e.g., pytest warnings). If you see deprecation warnings in your own code, address those before merge.

## Mocking Strategy

All tests use `unittest.mock` for isolation:
- Redis client is mocked
- Context is mocked
- No real Redis connection required
- Tests run in seconds

## Integration Testing (Optional)

To test with a real Redis instance:

```bash
# Start Redis locally (requires Docker)
docker run -d -p 6379:6379 redis:latest

# Run tests
pytest function/tests/ -v

# Stop Redis
docker stop <container_id>
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'function'`
**Solution:** Run pytest from the `template/netwrix-python/` directory

### `ImportError: cannot import name 'StateManager'`
**Solution:** Ensure you're in the correct directory where function/ exists

### Tests seem slow
**Solution:** Use `-v` for verbose output to see what's running

### One test fails
**Solution:** Run just that test with `-x` to stop on first failure

## CI/CD Integration

For automated testing, add to your CI/CD pipeline:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    cd dspm-connector-templates/template/netwrix-python
    pip install pytest
    pytest function/tests/ -v
```

## Next Steps

After tests pass:
1. ✅ Run tests locally
2. ✅ Review code coverage
3. ✅ Commit changes
4. ✅ Push and create PR
5. ✅ Get code review
6. ✅ Merge to main

---

**Happy testing!** 🚀
