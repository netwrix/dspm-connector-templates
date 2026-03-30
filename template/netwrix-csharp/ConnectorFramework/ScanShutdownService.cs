namespace Netwrix.ConnectorFramework;

/// <summary>
/// Singleton that carries the active scan's shutdown signal across all DI scopes.
/// Because it lives outside the per-request scope, any scope that receives a STOP signal
/// can cancel the token and all other scopes will observe the cancellation immediately.
///
/// In job mode (one container = one execution) no reset is needed.
/// In HTTP mode, call <see cref="Reset"/> before starting a new scan if the previous
/// execution has already completed and you want a fresh token.
/// </summary>
public sealed class ScanShutdownService : IDisposable
{
    private CancellationTokenSource _cts = new();

    /// <summary>The token that is cancelled when a STOP signal is received.</summary>
    public CancellationToken Token => _cts.Token;

    /// <summary>Returns true after <see cref="Cancel"/> has been called.</summary>
    public bool IsCancellationRequested => _cts.IsCancellationRequested;

    /// <summary>Signals shutdown to all observers of <see cref="Token"/>.</summary>
    public void Cancel()
    {
        if (!_cts.IsCancellationRequested)
        {
            _cts.Cancel();
        }
    }

    /// <summary>
    /// Replaces the internal token source so the next scan starts with a fresh token.
    /// Must be called only when no scan is actively running.
    /// </summary>
    public void Reset()
    {
        var old = _cts;
        _cts = new CancellationTokenSource();
        old.Dispose();
    }

    public void Dispose() => _cts.Dispose();
}
