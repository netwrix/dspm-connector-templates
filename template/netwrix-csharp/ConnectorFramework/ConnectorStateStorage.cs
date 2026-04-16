using System.Runtime.CompilerServices;
using System.Text.Json;
using Netwrix.Overlord.Sdk.Core.Storage;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;
namespace Netwrix.ConnectorFramework;

/// <summary>
/// <see cref="IStateStorage"/> implementation backed by the connector-state HTTP service.
/// Values are JSON-serialized and stored as strings.
/// </summary>
public sealed class ConnectorStateStorage : IStateStorage
{

    private readonly string? _scanId;
    private readonly string? _scanExecutionId;
    private readonly ConnectorStateClient _stateClient;
    private readonly ILogger<ConnectorStateStorage> _logger;

    /// <summary>
    /// Scoped DI constructor — used when resolving from a request context.
    /// </summary>
    public ConnectorStateStorage(
        ConnectorRequestData request,
        ConnectorStateClient stateClient,
        ILogger<ConnectorStateStorage> logger)
        : this(request.Execution.ScanId, request.Execution.ScanExecutionId, stateClient, logger)
    {
    }

    /// <summary>
    /// Factory constructor — used by <see cref="ConnectorRunStateStorageFactory"/> to create
    /// instances without requiring a live request scope (e.g. inside the singleton orchestrator).
    /// Must remain <c>public</c>: connector assemblies are not listed in InternalsVisibleTo.
    /// </summary>
    public ConnectorStateStorage(
        string? scanId,
        string? scanExecutionId,
        ConnectorStateClient stateClient,
        ILogger<ConnectorStateStorage> logger)
    {
        _scanId = scanId;
        _scanExecutionId = scanExecutionId;
        _stateClient = stateClient;
        _logger = logger;
    }

    // ── IStateStorage ────────────────────────────────────────────────────────

    public async Task<TryGetResult<T>> TryGetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        if (_scanId is null)
        {
            _logger.LogWarning("TryGetAsync called but ScanId is null — returning NotFound");
            return TryGetResult<T>.NotFound;
        }

        var allState = await FetchAllStateAsync(cancellationToken);

        if (!allState.TryGetValue(key, out var json))
        {
            return TryGetResult<T>.NotFound;
        }

        var value = Deserialize<T>(key, json);

        return new TryGetResult<T>(value);
    }

    public async Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(value);

        if (_scanId is null)
        {
            _logger.LogWarning("SetAsync called but ScanId is null — skipping");
            return;
        }

        var json = Serialize(key, value);

        await WriteStateAsync(new Dictionary<string, string> { [key] = json }, cancellationToken);
    }

    public async Task<string> SetIfMatchAsync<T>(string key, T value, string? expectedETag, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(value);

        if (_scanId is null)
        {
            throw new StateStorageException($"SetIfMatchAsync called but ScanId is null — cannot write state for key: {key}");
        }

        // The connector-state service does not support optimistic concurrency (ETags).
        // expectedETag is intentionally ignored; the write is always unconditional.
        // Return string.Empty to signal "no ETag" per the IStateStorage contract.
        var json = Serialize(key, value);
        await WriteStateAsync(new Dictionary<string, string> { [key] = json }, cancellationToken);
        return string.Empty;
    }

    public async Task<bool> DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        if (_scanId is null)
        {
            _logger.LogWarning("DeleteAsync called but ScanId is null — skipping");
            return false;
        }

        await DeleteStateAsync(new[] { key }, cancellationToken);
        return true;
    }

    public async Task DeleteAllAsync(string keyPrefix, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyPrefix);

        if (_scanId is null)
        {
            _logger.LogWarning("DeleteAllAsync called but ScanId is null — skipping");
            return;
        }

        var allState = await FetchAllStateAsync(cancellationToken);

        var toDelete = allState.Keys
            .Where(k => MatchesPrefix(k, keyPrefix))
            .ToArray();

        if (toDelete.Length == 0)
        {
            return;
        }

        await DeleteStateAsync(toDelete, cancellationToken);
    }

    public IAsyncEnumerable<string> ListAllKeysAsync(string keyPrefix = "", CancellationToken cancellationToken = default)
        => ListAllKeysCoreAsync(keyPrefix, cancellationToken);

    public IAsyncEnumerable<string> ListKeysAsync(string keyPrefix, int depth = 1, CancellationToken cancellationToken = default)
    {
        // Validate eagerly: the interface contract says ArgumentOutOfRangeException is thrown by this
        // method, not deferred to first enumeration (which is the normal async-iterator trap).
        if (depth < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(depth), "depth must be >= 1.");
        }

        return ListKeysCoreAsync(keyPrefix, depth, cancellationToken);
    }

    // ── Async iterators ──────────────────────────────────────────────────────

    private async IAsyncEnumerable<string> ListAllKeysCoreAsync(
        string keyPrefix,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (_scanId is null)
        {
            _logger.LogWarning("ListAllKeysAsync called but ScanId is null — returning empty");
            yield break;
        }

        var allState = await FetchAllStateAsync(cancellationToken);

        foreach (var key in allState.Keys
            .Where(k => MatchesPrefix(k, keyPrefix))
            .Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return key;
        }
    }

    private async IAsyncEnumerable<string> ListKeysCoreAsync(
        string keyPrefix,
        int depth,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var trimmedPrefix = keyPrefix.Trim('/');
        var prefixSegments = string.IsNullOrEmpty(trimmedPrefix) ? 0 : trimmedPrefix.Count(c => c == '/') + 1;
        var targetSlashCount = prefixSegments + depth - 1;

        await foreach (var key in ListAllKeysCoreAsync(keyPrefix, cancellationToken).ConfigureAwait(false))
        {
            if (key.Count(c => c == '/') == targetSlashCount)
            {
                yield return key;
            }
        }
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────────

    private Task<Dictionary<string, string>> FetchAllStateAsync(CancellationToken ct)
        => _stateClient.GetStateAsync(_scanId!, _scanExecutionId, ct);

    private Task WriteStateAsync(Dictionary<string, string> data, CancellationToken ct)
        => _stateClient.PostStateAsync(_scanId!, _scanExecutionId, data, ct);

    private Task DeleteStateAsync(string[] names, CancellationToken ct)
        => _stateClient.DeleteManyAsync(_scanId!, _scanExecutionId, names, ct);

    // ── Serialization ────────────────────────────────────────────────────────

    private static T Deserialize<T>(string key, string json)
    {
        try
        {
            var value = JsonSerializer.Deserialize<T>(json);
            if (value is null)
            {
                throw new StateStorageException($"Deserialization returned null for key: {key}");
            }

            return value!;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (JsonException ex)
        {
            throw new StateStorageException($"Failed to deserialize state at key: {key}", ex);
        }
    }

    private static string Serialize<T>(string key, T value)
    {
        try
        {
            return JsonSerializer.Serialize(value);
        }
        catch (JsonException ex)
        {
            throw new StateStorageException($"Failed to serialize state for key: {key}", ex);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static bool MatchesPrefix(string key, string prefix)
    {
        if (string.IsNullOrEmpty(prefix))
        {
            return true;
        }

        var normalizedPrefix = prefix.TrimEnd('/');
        return key == normalizedPrefix
            || key.StartsWith(normalizedPrefix + "/", StringComparison.Ordinal);
    }
}
