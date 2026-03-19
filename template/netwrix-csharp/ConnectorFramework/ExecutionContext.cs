namespace Netwrix.ConnectorFramework;

public sealed record ExecutionContext(
    string? ScanId,
    string? ScanExecutionId,
    string? SourceId,
    string? SourceType,
    string? SourceVersion,
    string? FunctionType
)
{
    /// <summary>
    /// Returns true for function types that run long enough to warrant status updates
    /// (Running → Completed/Failed) during job execution.
    /// </summary>
    public bool IsLongRunning => FunctionType is "access-scan" or "sync";
}
