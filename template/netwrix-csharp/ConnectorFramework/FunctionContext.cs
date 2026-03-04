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
    private readonly RedisSignalHandler _redis;
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
        RedisSignalHandler redis,
        ILogger<FunctionContext> logger,
        ILoggerFactory loggerFactory)
    {
        Request = request;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _redis = redis;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    private IReadOnlyDictionary<string, string>? _secrets;

    /// <summary>
    /// Lazily loads secrets from /var/secrets/{name} (connector-api) or /var/openfaas/secrets/{name} (fallback).
    /// Access secrets via context.Secrets["my-secret"].
    /// </summary>
    public IReadOnlyDictionary<string, string> Secrets => _secrets ??= LoadSecrets();

    private static IReadOnlyDictionary<string, string> LoadSecrets()
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
            _loggerFactory.CreateLogger<BatchManager>()));

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

    // ── Checkpoint API ───────────────────────────────────────────────────────

    /// <summary>
    /// Reads the connector's pause/resume checkpoint state from Redis.
    /// Returns null if no state has been saved.
    /// </summary>
    public Task<T?> GetConnectorStateAsync<T>(CancellationToken ct = default)
    {
        if (ScanExecutionId is null)
        {
            return Task.FromResult<T?>(default);
        }

        return _redis.GetStateAsync<T>(ScanExecutionId, ct);
    }

    /// <summary>
    /// Saves connector checkpoint state to Redis (TTL 24h).
    /// </summary>
    public Task SetConnectorStateAsync<T>(T state, CancellationToken ct = default)
    {
        if (ScanExecutionId is null)
        {
            return Task.CompletedTask;
        }

        return _redis.SetStateAsync(ScanExecutionId, state, ct);
    }

    /// <summary>
    /// Deletes the connector checkpoint state for the current execution.
    /// </summary>
    public Task DeleteConnectorStateAsync(CancellationToken ct = default)
    {
        if (ScanExecutionId is null)
        {
            return Task.CompletedTask;
        }

        return _redis.DeleteStateAsync(ScanExecutionId, ct);
    }

    /// <summary>
    /// Reads checkpoint state saved by a prior execution (e.g., the paused run being resumed).
    /// The prior execution ID is read from the <c>PRIOR_SCAN_EXECUTION_ID</c> environment variable.
    /// <para>
    /// <b>Limitation:</b> this reads from Redis only (<c>scan:state:{priorId}</c>).
    /// If <c>REDIS_URL</c> is not configured, or the prior execution's state has expired (TTL 24h),
    /// this method returns <c>null</c>.
    /// Connectors that need durable resume state independent of Redis should call the
    /// <c>connector-state</c> HTTP service directly via <c>IHttpClientFactory</c>.
    /// </para>
    /// </summary>
    public Task<T?> GetPriorExecutionAsync<T>(CancellationToken ct = default)
    {
        var priorId = Environment.GetEnvironmentVariable("PRIOR_SCAN_EXECUTION_ID");
        if (string.IsNullOrEmpty(priorId))
        {
            return Task.FromResult<T?>(default);
        }

        return _redis.GetStateAsync<T>(priorId, ct);
    }

    // ── Standard responses ───────────────────────────────────────────────────

    public static object TestConnectionSuccessResponse()
        => new { statusCode = 200, body = new { } };

    public static object AccessScanSuccessResponse()
        => new { statusCode = 200, body = new { } };

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
