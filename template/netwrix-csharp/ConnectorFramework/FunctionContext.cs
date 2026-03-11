using System.Diagnostics;
using System.Text.Json;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Per-request context provided to every connector operation.
/// Injected by the framework via DI (Scoped lifetime).
/// </summary>
public sealed class FunctionContext : IAsyncDisposable
{
    private static readonly ActivitySource ActivitySource = new("Netwrix.ConnectorFramework");

    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<FunctionContext> _logger;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, BatchManager> _tables = new();
    private readonly ILoggerFactory _loggerFactory;

    public ConnectorRequestData Request { get; }
    public string? ScanId => Request.ScanId;
    public string? ScanExecutionId => Request.ScanExecutionId;

    /// <summary>Structured logger with automatic scan-context enrichment.</summary>
    public ILogger Log => _logger;

    public FunctionContext(
        ConnectorRequestData request,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ILogger<FunctionContext> logger,
        ILoggerFactory loggerFactory)
    {
        Request = request;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    private IReadOnlyDictionary<string, string>? _secrets;

    /// <summary>
    /// Lazily loads secrets from /var/secrets/{name} (connector-api) or /var/openfaas/secrets/{name} (fallback).
    /// Applies SECRET_MAPPINGS env var aliases after loading (format: "key1:secretName1,key2:secretName2").
    /// Access secrets via context.Secrets["my-secret"].
    /// </summary>
    public IReadOnlyDictionary<string, string> Secrets => _secrets ??= LoadSecrets();

    private IReadOnlyDictionary<string, string> LoadSecrets()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var basePath in new[] { "/var/secrets", "/var/openfaas/secrets" })
        {
            if (!Directory.Exists(basePath))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(basePath))
            {
                // Path traversal guard
                var resolved = Path.GetFullPath(file);
                if (!resolved.StartsWith(Path.GetFullPath(basePath), StringComparison.Ordinal))
                {
                    continue;
                }

                var key = Path.GetFileName(file);
                if (!dict.ContainsKey(key))
                {
                    dict[key] = File.ReadAllText(file).Trim();
                }
            }
        }

        // Apply SECRET_MAPPINGS aliases: "appKey1:secretFile1,appKey2:secretFile2"
        var mappings = Environment.GetEnvironmentVariable("SECRET_MAPPINGS") ?? "";
        foreach (var mapping in mappings.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = mapping.Split(':', 2);
            if (parts.Length != 2)
            {
                continue;
            }

            var aliasKey = parts[0].Trim();
            var secretName = parts[1].Trim();
            if (dict.TryGetValue(secretName, out var value))
            {
                dict[aliasKey] = value;
            }
            else
            {
                _logger.LogWarning("SECRET_MAPPINGS: secret {SecretName} not found for key {AliasKey}", secretName, aliasKey);
            }
        }

        return dict;
    }

    // ── Tables / BatchManager ────────────────────────────────────────────────

    /// <summary>
    /// Returns (or lazily creates) a <see cref="BatchManager"/> for the given table name.
    /// Use this to buffer and flush scanned objects to the data-ingestion service.
    /// </summary>
    public BatchManager GetTable(string tableName)
        => _tables.GetOrAdd(tableName, name => new BatchManager(
            name,
            _httpClientFactory,
            Request,
            _loggerFactory.CreateLogger<BatchManager>(),
            onFlushed: (count, ct) => UpdateExecutionAsync(incrementCompletedObjects: count, ct: ct)));

    /// <summary>
    /// Adds an object to the named table's batch buffer.
    /// Shorthand for <c>GetTable(table).AddObject(obj, updateStatus)</c>.
    /// </summary>
    public void SaveObject(string table, object obj, bool updateStatus = true)
        => GetTable(table).AddObject(obj, updateStatus);

    /// <summary>
    /// Flushes all active table batch managers. The framework calls this automatically
    /// after a job-mode invocation completes.
    /// </summary>
    public async Task FlushTablesAsync(CancellationToken ct = default)
    {
        foreach (var (_, bm) in _tables)
        {
            await bm.FlushAsync(ct);
        }
    }

    // ── OpenTelemetry ────────────────────────────────────────────────────────

    /// <summary>
    /// Starts a new span. Always use with <c>using</c>:
    /// <code>using var activity = context.StartActivity("my-operation");</code>
    /// </summary>
    public Activity? StartActivity(string name)
        => ActivitySource.StartActivity(name);

    // ── Caller headers ───────────────────────────────────────────────────────

    /// <summary>
    /// Returns headers that propagate scan context and W3C trace context to downstream HTTP calls.
    /// </summary>
    public IReadOnlyDictionary<string, string> GetCallerHeaders()
    {
        var headers = new Dictionary<string, string>();

        if (ScanId is not null)
        {
            headers["Scan-Id"] = ScanId;
        }

        if (ScanExecutionId is not null)
        {
            headers["Scan-Execution-Id"] = ScanExecutionId;
        }

        var functionType = Environment.GetEnvironmentVariable("FUNCTION_TYPE") ?? "netwrix";
        headers["Function-Type"] = functionType;

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

    // ── UpdateExecution ──────────────────────────────────────────────────────

    /// <summary>
    /// Reports scan progress to the upstream connector-api.
    /// Call this at meaningful progress milestones, not after every object.
    /// </summary>
    public async Task UpdateExecutionAsync(
        string? status = null,
        int? totalObjects = null,
        int? completedObjects = null,
        DateTimeOffset? completedAt = null,
        int incrementCompletedObjects = 0,
        CancellationToken ct = default)
    {
        if (ScanExecutionId is null)
        {
            _logger.LogWarning("UpdateExecutionAsync called but ScanExecutionId is null — skipping");
            return;
        }

        var payload = new Dictionary<string, object> { ["executionId"] = ScanExecutionId };
        if (status is not null)
        {
            payload["status"] = status;
        }

        if (totalObjects is not null)
        {
            payload["totalObjects"] = totalObjects.Value;
        }

        if (completedObjects is not null)
        {
            payload["completedObjects"] = completedObjects.Value;
        }

        if (completedAt is not null)
        {
            payload["completedAt"] = completedAt.Value;
        }

        if (incrementCompletedObjects > 0)
        {
            payload["incrementCompletedObjects"] = incrementCompletedObjects;
        }

        var serviceUrl = ServiceUrlHelper.Resolve("APP_UPDATE_EXECUTION_FUNCTION", "app-update-execution");

        try
        {
            using var client = _httpClientFactory.CreateClient("update-execution");
            using var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json"),
            };
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("UpdateExecution returned {StatusCode}", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UpdateExecution failed for execution {ExecutionId}", ScanExecutionId);
        }
    }

    // ── Connector State API ──────────────────────────────────────────────────

    /// <summary>
    /// Retrieves connector state from the connector-state service, keyed by scan ID.
    /// Returns null if ScanId is not set or on error.
    /// </summary>
    public async Task<Dictionary<string, string>?> GetConnectorStateAsync(CancellationToken ct = default)
    {
        if (ScanId is null)
        {
            _logger.LogWarning("GetConnectorStateAsync called but ScanId is null — skipping");
            return null;
        }

        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var url = $"{serviceUrl}?scanId={Uri.EscapeDataString(ScanId)}";

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetConnectorState returned {StatusCode}", (int)response.StatusCode);
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var error = root.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Unknown error";
                _logger.LogWarning("GetConnectorState failed: {Error}", error);
                return null;
            }

            if (root.TryGetProperty("data", out var dataProp))
            {
                return dataProp.Deserialize<Dictionary<string, string>>();
            }

            return new Dictionary<string, string>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetConnectorState failed for scan {ScanId}", ScanId);
            return null;
        }
    }

    /// <summary>
    /// Saves connector state to the connector-state service, keyed by scan ID.
    /// </summary>
    public async Task SetConnectorStateAsync(Dictionary<string, object?> data, CancellationToken ct = default)
    {
        if (ScanId is null)
        {
            _logger.LogWarning("SetConnectorStateAsync called but ScanId is null — skipping");
            return;
        }

        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var payload = new { scanId = ScanId, data };

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json"),
            };
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("SetConnectorState returned {StatusCode}", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SetConnectorState failed for scan {ScanId}", ScanId);
        }
    }

    /// <summary>
    /// Deletes connector state from the connector-state service.
    /// If <paramref name="names"/> is null, deletes all state for the current scan.
    /// </summary>
    public async Task DeleteConnectorStateAsync(string[]? names = null, CancellationToken ct = default)
    {
        if (ScanId is null)
        {
            _logger.LogWarning("DeleteConnectorStateAsync called but ScanId is null — skipping");
            return;
        }

        var serviceUrl = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
        var qs = $"?scanId={Uri.EscapeDataString(ScanId)}";
        if (names is { Length: > 0 })
        {
            qs += string.Concat(names.Select(n => $"&name[]={Uri.EscapeDataString(n)}"));
        }

        var url = serviceUrl + qs;

        try
        {
            using var client = _httpClientFactory.CreateClient("connector-state");
            using var request = new HttpRequestMessage(HttpMethod.Delete, url);
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("DeleteConnectorState returned {StatusCode}", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DeleteConnectorState failed for scan {ScanId}", ScanId);
        }
    }

    /// <summary>
    /// Queries the app-data-query service for a prior scan execution by ID.
    /// Returns null if not found or on error.
    /// </summary>
    public async Task<PriorExecution?> GetPriorExecutionAsync(string scanExecutionId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(scanExecutionId))
        {
            return null;
        }

        var serviceUrl = ServiceUrlHelper.Resolve("APP_DATA_QUERY_FUNCTION", "app-data-query");
        var query = $"SELECT id, status, completed_objects FROM scan_executions WHERE id = '{scanExecutionId}' LIMIT 1";
        var payload = new { query };

        try
        {
            using var client = _httpClientFactory.CreateClient("app-data-query");
            using var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json"),
            };
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetPriorExecution returned {StatusCode}", (int)response.StatusCode);
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                return null;
            }

            if (!root.TryGetProperty("data", out var dataProp) || dataProp.GetArrayLength() == 0)
            {
                return null;
            }

            var first = dataProp[0];
            var id = first.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
            var status = first.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? "" : "";
            var coValue = first.TryGetProperty("completed_objects", out var coProp) ? coProp.GetInt32() : 0;

            if (coValue <= 0)
            {
                _logger.LogInformation("No prior execution found for {ScanExecutionId}", scanExecutionId);
                return null;
            }

            _logger.LogInformation(
                "Retrieved prior execution {ScanExecutionId}: status={Status}, completedObjects={CompletedObjects}",
                scanExecutionId, status, coValue);

            return new PriorExecution(id, status, coValue);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error querying prior execution {ScanExecutionId}", scanExecutionId);
            return null;
        }
    }

    // ── Standard responses ───────────────────────────────────────────────────

    public static object TestConnectionSuccessResponse()
        => new { statusCode = 200, body = new { } };

    public static object AccessScanSuccessResponse()
        => new { statusCode = 200, body = new { } };

    public static object GetObjectSuccessResponse(byte[] data)
        => new { statusCode = 200, body = new { data = Convert.ToBase64String(data) } };

    public static object ErrorResponse(bool clientError, string message)
        => new { statusCode = clientError ? 400 : 500, body = new { error = message } };

    // ── Dispose ──────────────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        foreach (var (_, bm) in _tables)
        {
            await bm.FlushAsync();
            await bm.DisposeAsync();
        }
    }
}

/// <summary>
/// Represents a prior scan execution returned from the app-data-query service.
/// </summary>
public sealed record PriorExecution(string Id, string Status, int CompletedObjects);
