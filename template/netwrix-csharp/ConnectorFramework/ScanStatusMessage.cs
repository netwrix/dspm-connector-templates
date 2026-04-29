using System.Text.Json.Serialization;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Schema for entries written to the <c>scan:status:{executionId}</c> Redis stream.
/// Serialized as a single <c>data</c> field in each stream entry.
/// </summary>
public sealed record ScanStatusMessage
{
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("scan_execution_id")]
    public required string ScanExecutionId { get; init; }

    [JsonPropertyName("timestamp")]
    public required DateTimeOffset Timestamp { get; init; }

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("partial_data")]
    public bool PartialData { get; init; }

    [JsonPropertyName("objects_count")]
    public int ObjectsCount { get; init; }

    [JsonPropertyName("failed_paths_count")]
    public int FailedPathsCount { get; init; }
}
