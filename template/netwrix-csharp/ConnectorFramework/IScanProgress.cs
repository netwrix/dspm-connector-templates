using System.Diagnostics;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Abstraction over the progress/telemetry side of <see cref="FunctionContext"/>.
/// Implemented by <see cref="FunctionContext"/>; inject this interface into facades
/// that need to report scan progress or emit OpenTelemetry spans.
/// </summary>
public interface IScanProgress
{
    ExecutionContext Execution { get; }
    Activity? StartActivity(string name);
    Task UpdateExecutionAsync(
        string? status = null,
        int? totalObjects = null,
        int? completedObjects = null,
        DateTimeOffset? completedAt = null,
        int incrementCompletedObjects = 0,
        CancellationToken ct = default);
}
