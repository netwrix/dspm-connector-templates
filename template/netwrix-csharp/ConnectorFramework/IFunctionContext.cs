using System.Diagnostics;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Per-request context provided to every connector operation.
/// Implement <see cref="FunctionContext"/> in production; use a test double in unit tests.
/// </summary>
public interface IFunctionContext
{
    ExecutionContext Execution { get; }
    ILogger Log { get; }
    IReadOnlyDictionary<string, string> Secrets { get; }
    ConnectorRequestData Request { get; }

    Activity? StartActivity(string name);
    BatchManager GetTable(string tableName);

    Task UpdateExecutionAsync(
        string? status = null,
        int? totalObjects = null,
        int? completedObjects = null,
        DateTimeOffset? completedAt = null,
        int incrementCompletedObjects = 0,
        CancellationToken ct = default);

    Task<Dictionary<string, string>?> GetConnectorStateAsync(CancellationToken ct = default);
    Task SetConnectorStateAsync(Dictionary<string, object?> data, CancellationToken ct = default);
    Task FlushTablesAsync(CancellationToken ct = default);
}
