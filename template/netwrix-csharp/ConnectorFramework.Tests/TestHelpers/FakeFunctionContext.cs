using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

/// <summary>
/// In-memory IFunctionContext for unit tests. Pre-seed secrets and state via the constructor;
/// inspect captured UpdateExecutionAsync calls via <see cref="ExecutionUpdates"/>.
/// </summary>
public sealed class FakeFunctionContext : IFunctionContext
{
    private Dictionary<string, string>? _state;

    public FakeFunctionContext(
        Dictionary<string, string>? secrets = null,
        Dictionary<string, string>? initialState = null,
        ExecutionContext? execution = null)
    {
        Secrets = secrets ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        _state = initialState;
        Execution = execution ?? new ExecutionContext(
            ScanId: "test-scan",
            ScanExecutionId: "test-execution",
            SourceId: "test-source",
            SourceType: "test",
            SourceVersion: null,
            FunctionType: "access-scan");
        Request = new ConnectorRequestData(
            Method: "POST",
            Path: "/connector/access_scan",
            Headers: new Dictionary<string, string>(),
            Body: null,
            Execution: Execution);
    }

    public ExecutionContext Execution { get; }
    public ILogger Log => NullLogger.Instance;
    public IReadOnlyDictionary<string, string> Secrets { get; }
    public ConnectorRequestData Request { get; }

    public List<UpdateExecutionCall> ExecutionUpdates { get; } = new();

    public Activity? StartActivity(string name) => null;

    /// <summary>
    /// Not supported — BatchManager requires real HTTP infrastructure.
    /// Connector unit tests should inject IScanWriter directly.
    /// </summary>
    public BatchManager GetTable(string tableName)
        => throw new NotSupportedException(
            "GetTable is not available in FakeFunctionContext. " +
            "Inject IScanWriter directly for unit tests that need data capture.");

    public Task UpdateExecutionAsync(
        string? status = null,
        int? totalObjects = null,
        int? completedObjects = null,
        DateTimeOffset? completedAt = null,
        int incrementCompletedObjects = 0,
        CancellationToken ct = default)
    {
        ExecutionUpdates.Add(new UpdateExecutionCall(status, totalObjects, completedObjects, completedAt, incrementCompletedObjects));
        return Task.CompletedTask;
    }

    public Task<Dictionary<string, string>?> GetConnectorStateAsync(CancellationToken ct = default)
        => Task.FromResult(_state);

    public Task SetConnectorStateAsync(Dictionary<string, object?> data, CancellationToken ct = default)
    {
        _state ??= new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in data)
        {
            if (value is not null)
            {
                _state[key] = value.ToString() ?? string.Empty;
            }
        }

        return Task.CompletedTask;
    }

    public Task FlushTablesAsync(CancellationToken ct = default) => Task.CompletedTask;
}

public sealed record UpdateExecutionCall(
    string? Status,
    int? TotalObjects,
    int? CompletedObjects,
    DateTimeOffset? CompletedAt,
    int IncrementCompletedObjects);
