using System.Text.Json;
using StackExchange.Redis;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Reads/writes Redis Streams for scan control signals and status updates.
/// The IConnectionMultiplexer is a Singleton; this class is Scoped (carries per-scan stream offsets).
/// </summary>
public class RedisSignalHandler
{
    private const int StreamTtlSeconds = 86400; // 24 hours
    private const long StreamMaxLen = 100;

    private readonly IConnectionMultiplexer? _multiplexer;
    private readonly ILogger<RedisSignalHandler> _logger;

    private string _lastControlId = "0";

    public RedisSignalHandler(IConnectionMultiplexer? multiplexer, ILogger<RedisSignalHandler> logger)
    {
        _multiplexer = multiplexer;
        _logger = logger;
    }

    /// <summary>
    /// Non-blocking read of the next control signal after <paramref name="lastId"/>.
    /// Returns null if no signal is available or Redis is unreachable.
    /// </summary>
    public virtual async Task<(string Action, string MessageId)?> CheckControlSignalAsync(
        string executionId,
        string? lastId = null,
        CancellationToken ct = default)
    {
        lastId ??= _lastControlId;
        var key = $"scan:control:{executionId}";

        if (_multiplexer is null)
        {
            return null;
        }

        try
        {
            var db = _multiplexer.GetDatabase();
            var results = await db.StreamReadAsync(key, lastId, count: 1);

            if (results is not { Length: > 0 })
            {
                return null;
            }

            var entry = results[0];
            var messageId = entry.Id.ToString();
            _lastControlId = messageId;

            var action = entry.Values
                .Where(v => v.Name == "action")
                .Select(v => v.Value.ToString())
                .FirstOrDefault();

            if (action is null)
            {
                return null;
            }

            return (action, messageId);
        }
        catch (RedisException ex)
        {
            _logger.LogWarning(ex, "Redis error reading control signal for execution {ExecutionId}", executionId);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading control signal for execution {ExecutionId}", executionId);
            return null;
        }
    }

    /// <summary>
    /// Appends a status update to the scan:status stream and sets a 24h TTL.
    /// </summary>
    public virtual async Task UpdateStatusAsync(
        string executionId,
        string status,
        string message = "",
        bool partialData = false,
        int objectsCount = 0,
        int failedPathsCount = 0,
        CancellationToken ct = default)
    {
        if (_multiplexer is null)
        {
            return;
        }

        var key = $"scan:status:{executionId}";

        try
        {
            var db = _multiplexer.GetDatabase();
            var fields = new NameValueEntry[]
            {
                new("status", status),
                new("timestamp", DateTimeOffset.UtcNow.ToString("O")),
                new("message", message),
                new("partial_data", partialData.ToString().ToLowerInvariant()),
                new("objects_count", objectsCount.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                new("failed_paths_count", failedPathsCount.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            };

            await db.StreamAddAsync(key, fields, maxLength: StreamMaxLen, useApproximateMaxLength: true);
            await db.KeyExpireAsync(key, TimeSpan.FromSeconds(StreamTtlSeconds));

            _logger.LogInformation("Status updated for execution {ExecutionId}: {Status}", executionId, status);
        }
        catch (RedisException ex)
        {
            _logger.LogWarning(ex, "Redis error updating status for execution {ExecutionId}", executionId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to update status for execution {ExecutionId}", executionId);
        }
    }

    /// <summary>
    /// Deletes both the control and status streams for a completed scan.
    /// </summary>
    public virtual async Task CleanupStreamsAsync(string executionId, CancellationToken ct = default)
    {
        if (_multiplexer is null)
        {
            return;
        }

        var keys = new RedisKey[]
        {
            $"scan:control:{executionId}",
            $"scan:status:{executionId}",
        };

        try
        {
            var db = _multiplexer.GetDatabase();
            var deleted = await db.KeyDeleteAsync(keys);
            _logger.LogInformation("Streams cleaned up for execution {ExecutionId}: {Count} keys deleted", executionId, deleted);
        }
        catch (RedisException ex)
        {
            _logger.LogWarning(ex, "Redis error cleaning up streams for execution {ExecutionId}", executionId);
        }
    }

    // ── Checkpoint API ────────────────────────────────────────────────────────

    private static string StateKey(string executionId) => $"scan:state:{executionId}";

    /// <summary>
    /// Reads the connector checkpoint state saved by the current execution.
    /// Returns null if no state has been saved or Redis is unreachable.
    /// </summary>
    public async Task<T?> GetStateAsync<T>(string executionId, CancellationToken ct = default)
    {
        if (_multiplexer is null)
        {
            return default;
        }

        try
        {
            var db = _multiplexer.GetDatabase();
            var value = await db.StringGetAsync(StateKey(executionId));
            if (!value.HasValue)
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(value.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get connector state for execution {ExecutionId}", executionId);
            return default;
        }
    }

    /// <summary>
    /// Saves connector checkpoint state, TTL 24h, for pause/resume support.
    /// </summary>
    public async Task SetStateAsync<T>(string executionId, T state, CancellationToken ct = default)
    {
        if (_multiplexer is null)
        {
            return;
        }

        try
        {
            var db = _multiplexer.GetDatabase();
            var json = JsonSerializer.Serialize(state);
            await db.StringSetAsync(StateKey(executionId), json, TimeSpan.FromSeconds(StreamTtlSeconds));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to set connector state for execution {ExecutionId}", executionId);
        }
    }

    /// <summary>
    /// Deletes the connector checkpoint state for the current execution.
    /// </summary>
    public async Task DeleteStateAsync(string executionId, CancellationToken ct = default)
    {
        if (_multiplexer is null)
        {
            return;
        }

        try
        {
            var db = _multiplexer.GetDatabase();
            await db.KeyDeleteAsync(StateKey(executionId));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete connector state for execution {ExecutionId}", executionId);
        }
    }

    /// <summary>
    /// Checks whether Redis is reachable.
    /// </summary>
    public bool IsHealthy()
    {
        if (_multiplexer is null)
        {
            return false;
        }

        try
        {
            _multiplexer.GetDatabase().Ping();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
