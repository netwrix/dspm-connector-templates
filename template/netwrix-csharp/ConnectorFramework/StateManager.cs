namespace Netwrix.ConnectorFramework;
/// <summary>
/// Manages scan execution states (running/stopping/stopped/pausing/paused/resuming/completed/failed).
/// Uses SemaphoreSlim for all state mutations — safe to await inside async methods.
/// </summary>
public sealed class StateManager : IAsyncDisposable
{
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ValidTransitions =
        new Dictionary<string, IReadOnlyList<string>>
        {
            [ScanStatus.Running] = [ScanStatus.Stopping, ScanStatus.Pausing, ScanStatus.Completed, ScanStatus.CompletedWithErrors, ScanStatus.Failed],
            [ScanStatus.Stopping] = [ScanStatus.Stopped, ScanStatus.Failed],
            [ScanStatus.Stopped] = [],
            [ScanStatus.Pausing] = [ScanStatus.Paused, ScanStatus.Failed],
            [ScanStatus.Paused] = [ScanStatus.Resuming, ScanStatus.Failed, ScanStatus.Stopped],
            [ScanStatus.Resuming] = [ScanStatus.Running, ScanStatus.Failed],
            [ScanStatus.Completed] = [],
            [ScanStatus.CompletedWithErrors] = [],
            [ScanStatus.Failed] = [],
        };

    private readonly RedisSignalHandler _redis;
    private readonly ScanShutdownService _shutdown;
    private readonly IScanProgress _progress;
    private readonly ILogger<StateManager> _logger;
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private readonly List<Func<string, string, Task>> _callbacks = [];

    private volatile string _currentState = ScanStatus.Running;
    private string? _requestedState;
    private DateTimeOffset _lastSignalCheck = DateTimeOffset.MinValue;

    public SupportedStates SupportedStates { get; }
    public int SignalCheckIntervalSeconds { get; }

    /// <summary>
    /// A CancellationToken that is cancelled when a Redis STOP signal arrives or ShutdownAsync is called.
    /// Backed by the singleton <see cref="ScanShutdownService"/> so all DI scopes observe the same signal.
    /// Combine with Kestrel's token using CancellationTokenSource.CreateLinkedTokenSource.
    /// </summary>
    public CancellationToken Token => _shutdown.Token;

    public StateManager(
        RedisSignalHandler redis,
        ScanShutdownService shutdown,
        IScanProgress progress,
        ILogger<StateManager> logger,
        SupportedStates? supportedStates = null,
        int signalCheckIntervalSeconds = 5)
    {
        _redis = redis;
        _shutdown = shutdown;
        _progress = progress;
        _logger = logger;
        SupportedStates = supportedStates ?? new SupportedStates();
        SignalCheckIntervalSeconds = signalCheckIntervalSeconds;
    }

    // ── State queries ─────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the current state. Safe to read from any thread — backed by a volatile field.
    /// Writes still go through the semaphore to enforce valid transition logic.
    /// </summary>
    public string CurrentState => _currentState;

    public bool IsShutdown => _shutdown.IsCancellationRequested;

    // ── Signal monitoring ─────────────────────────────────────────────────────

    /// <summary>
    /// Polls Redis for control signals if the check interval has elapsed.
    /// Returns true if a STOP signal was received.
    /// </summary>
    public async Task<bool> ShouldStopAsync(string executionId, CancellationToken ct = default)
    {
        if (!SupportedStates.Stop)
        {
            return false;
        }

        await CheckForSignalsAsync(executionId, ct);

        await _semaphore.WaitAsync(ct);
        try { return _requestedState == "stop"; }
        finally { _semaphore.Release(); }
    }

    /// <summary>
    /// Polls Redis for control signals if the check interval has elapsed.
    /// Returns true if a PAUSE signal was received.
    /// </summary>
    public async Task<bool> ShouldPauseAsync(string executionId, CancellationToken ct = default)
    {
        if (!SupportedStates.Pause)
        {
            return false;
        }

        await CheckForSignalsAsync(executionId, ct);

        await _semaphore.WaitAsync(ct);
        try { return _requestedState == "pause"; }
        finally { _semaphore.Release(); }
    }

    private async Task CheckForSignalsAsync(string executionId, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;

        // Read and update atomically under the semaphore to prevent two concurrent callers
        // from both passing the interval check before either records that a check is in progress.
        await _semaphore.WaitAsync(ct);
        var shouldCheck = (now - _lastSignalCheck).TotalSeconds >= SignalCheckIntervalSeconds;
        if (shouldCheck)
        {
            _lastSignalCheck = now;
        }

        _semaphore.Release();

        if (!shouldCheck)
        {
            return;
        }

        try
        {
            var signal = await _redis.CheckControlSignalAsync(executionId, ct: ct);
            if (signal is null)
            {
                return;
            }

            var (action, _) = signal.Value;

            if (action == "STOP")
            {
                await SetStateInternalAsync("stopping", ct);
                await _semaphore.WaitAsync(ct);
                try { _requestedState = "stop"; }
                finally { _semaphore.Release(); }
                _logger.LogInformation("STOP signal received for execution {ExecutionId}", executionId);
            }
            else if (action == "PAUSE" && SupportedStates.Pause)
            {
                await SetStateInternalAsync("pausing", ct);
                await _semaphore.WaitAsync(ct);
                try { _requestedState = "pause"; }
                finally { _semaphore.Release(); }
                _logger.LogInformation("PAUSE signal received for execution {ExecutionId}", executionId);
            }
            else if (action == "RESUME" && SupportedStates.Resume)
            {
                await _semaphore.WaitAsync(ct);
                try { _requestedState = null; }
                finally { _semaphore.Release(); }
                _logger.LogInformation("RESUME signal received for execution {ExecutionId}", executionId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error checking signals for execution {ExecutionId}", executionId);
        }
    }

    // ── State transitions ─────────────────────────────────────────────────────

    /// <summary>
    /// Attempts to transition to <paramref name="newState"/>.
    /// Returns false if the transition is invalid from the current state.
    /// </summary>
    public async Task<bool> SetStateAsync(string newState, CancellationToken ct = default)
        => await SetStateInternalAsync(newState, ct);

    private async Task<bool> SetStateInternalAsync(string newState, CancellationToken ct)
    {
        string oldState;

        await _semaphore.WaitAsync(ct);
        try
        {
            if (newState == _currentState)
            {
                return true;
            }

            if (!ValidTransitions.TryGetValue(_currentState, out var allowed) || !allowed.Contains(newState))
            {
                _logger.LogWarning("Invalid state transition from {OldState} to {NewState}", _currentState, newState);
                return false;
            }

            oldState = _currentState;
            _currentState = newState;
            _logger.LogInformation("State transitioned from {OldState} to {NewState}", oldState, newState);
        }
        finally
        {
            _semaphore.Release();
        }

        // Fire callbacks outside the semaphore to avoid deadlocks
        await FireCallbacksAsync(oldState, newState);
        return true;
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Transitions to <paramref name="finalStatus"/>, publishes the status to Redis, and cancels the token.
    /// </summary>
    public async Task<bool> ShutdownAsync(
        string executionId,
        string finalStatus = ScanStatus.Stopped,
        CancellationToken ct = default)
    {
        try
        {
            if (!await SetStateInternalAsync(finalStatus, ct))
            {
                _logger.LogWarning("Could not transition to final state {FinalStatus}", finalStatus);
                return false;
            }

            await _progress.UpdateExecutionAsync(
                status: finalStatus,
                completedAt: finalStatus != ScanStatus.Paused ? DateTimeOffset.UtcNow : null,
                ct: ct);

            await _redis.UpdateStatusAsync(
                executionId,
                finalStatus,
                "Execution stopped",
                partialData: finalStatus == ScanStatus.Stopped,
                ct: ct);

            await _redis.CleanupStreamsAsync(executionId, ct);

            _shutdown.Cancel();
            _logger.LogInformation("StateManager shutdown with status {FinalStatus}", finalStatus);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during StateManager shutdown");
            return false;
        }
    }

    // ── Callbacks ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Registers an async callback invoked after every successful state transition.
    /// </summary>
    public void OnStateChange(Func<string, string, Task> callback)
        => _callbacks.Add(callback);

    private async Task FireCallbacksAsync(string oldState, string newState)
    {
        foreach (var cb in _callbacks)
        {
            try { await cb(oldState, newState); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in state change callback");
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _semaphore.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Declares which control operations this connector supports.
/// </summary>
public record SupportedStates(bool Stop = true, bool Pause = true, bool Resume = false);
