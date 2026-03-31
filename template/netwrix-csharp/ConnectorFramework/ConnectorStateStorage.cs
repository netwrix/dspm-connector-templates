using System.Diagnostics;
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

    private readonly ConnectorRequestData _request;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ConnectorStateStorage> _logger;

    public ConnectorStateStorage(
        ConnectorRequestData request,
        IHttpClientFactory httpClientFactory,
        ILogger<ConnectorStateStorage> logger)
    {
        _request = request;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    private string? ScanId => _request.Execution.ScanId;

    // ── IStateStorage ────────────────────────────────────────────────────────

    public async Task<TryGetResult<T>> TryGetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        if (ScanId is null)
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

        if (ScanId is null)
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

        if (ScanId is null)
        {
            throw new StateStorageException($"SetIfMatchAsync called but ScanId is null — cannot write state for key: {key}");
        }

        var json = Serialize(key, value);
        await WriteStateAsync(new Dictionary<string, string> { [key] = json }, cancellationToken);
        return string.Empty;
    }

    public async Task<bool> DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        if (ScanId is null)
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

        if (ScanId is null)
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
        if (ScanId is null)
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

    private async Task<Dictionary<string, string>> FetchAllStateAsync(CancellationToken ct)
    {
        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var url = $"{serviceUrl}?scanId={Uri.EscapeDataString(ScanId!)}";

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            foreach (var (k, v) in BuildCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException($"connector-state GET returned {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var error = root.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Unknown error";
                throw new StateStorageException($"connector-state GET failed: {error}");
            }

            if (root.TryGetProperty("data", out var dataProp))
            {
                return dataProp.Deserialize<Dictionary<string, string>>() ?? new Dictionary<string, string>();
            }

            return new Dictionary<string, string>();
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new StateStorageException($"connector-state GET failed for scan {ScanId}", ex);
        }
    }

    private async Task WriteStateAsync(Dictionary<string, string> data, CancellationToken ct)
    {
        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var payload = new { scanId = ScanId, data };

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json"),
            };
            foreach (var (k, v) in BuildCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException($"connector-state POST returned {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("success", out var successProp) && !successProp.GetBoolean())
                {
                    var error = root.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Unknown error";
                    throw new StateStorageException($"connector-state POST failed: {error}");
                }
            }
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new StateStorageException($"connector-state POST failed for scan {ScanId}", ex);
        }
    }

    private async Task DeleteStateAsync(string[] names, CancellationToken ct)
    {
        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var qs = $"?scanId={Uri.EscapeDataString(ScanId!)}";
        qs += string.Concat(names.Select(n => $"&name={Uri.EscapeDataString(n)}"));
        var url = serviceUrl + qs;

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Delete, url);
            foreach (var (k, v) in BuildCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException($"connector-state DELETE returned {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("success", out var successProp) && !successProp.GetBoolean())
                {
                    var error = root.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Unknown error";
                    throw new StateStorageException($"connector-state DELETE failed: {error}");
                }
            }
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new StateStorageException($"connector-state DELETE failed for scan {ScanId}", ex);
        }
    }

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

    private Dictionary<string, string> BuildCallerHeaders()
    {
        var headers = new Dictionary<string, string>();

        if (_request.Execution.ScanId is not null)
        {
            headers["Scan-Id"] = _request.Execution.ScanId;
        }

        if (_request.Execution.ScanExecutionId is not null)
        {
            headers["Scan-Execution-Id"] = _request.Execution.ScanExecutionId;
        }

        headers["Function-Type"] = Environment.GetEnvironmentVariable("FUNCTION_TYPE") ?? "netwrix";

        var current = Activity.Current;
        if (current is not null)
        {
            if (current.Id is not null)
            {
                headers["traceparent"] = current.Id;
            }

            if (!string.IsNullOrEmpty(current.TraceStateString))
            {
                headers["tracestate"] = current.TraceStateString;
            }
        }

        return headers;
    }

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
