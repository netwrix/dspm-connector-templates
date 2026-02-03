using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace function;

public class FunctionContext
{
    private readonly HttpContext _httpContext;
    private readonly ILogger<FunctionContext> _logger;
    private readonly string _serviceName;
    private readonly ILoggerFactory _loggerFactory;

    public FunctionContext(HttpContext httpContext, ILogger<FunctionContext> logger, ILoggerFactory loggerFactory)
    {
        _httpContext = httpContext;
        _logger = logger;
        _loggerFactory = loggerFactory;

        // Build service name matching pattern
        var sourceType = Environment.GetEnvironmentVariable("SOURCE_TYPE") ?? "internal";
        var functionType = Environment.GetEnvironmentVariable("FUNCTION_TYPE") ?? "netwrix";
        _serviceName = $"{sourceType}-{functionType}";

        // Initialize properties
        ScanId = Environment.GetEnvironmentVariable("SCAN_ID");
        SyncId = Environment.GetEnvironmentVariable("SYNC_ID");
        FunctionType = functionType;

        Secrets = new Dictionary<string, string>();

        // Extract caller attributes from request headers
        CallerAttributes = new Dictionary<string, string>();
        if (_httpContext.Request.Headers.TryGetValue("Scan-Id", out var scanIdHeader))
        {
            CallerAttributes["scan_id"] = scanIdHeader.ToString();
        }
        if (_httpContext.Request.Headers.TryGetValue("Scan-Execution-Id", out var scanExecutionIdHeader))
        {
            CallerAttributes["scan_execution_id"] = scanExecutionIdHeader.ToString();
        }
    }

    public Dictionary<string, string> Secrets { get; private set; }
    public string? ScanId { get; set; }
    public string? SyncId { get; set; }
    public Guid ScanExecutionId { get; set; }
    public Guid SyncExecutionId { get; set; }
    public string? FunctionType { get; set; }
    public Guid SourceId { get; set; }
    public Dictionary<string, string> CallerAttributes { get; private set; }

    public void LoadSecrets()
    {
        var secretMappings = Environment.GetEnvironmentVariable("SECRET_MAPPINGS") ?? "";
        var mappings = secretMappings.Split(',', StringSplitOptions.RemoveEmptyEntries);

        foreach (var mapping in mappings)
        {
            var parts = mapping.Split(':');
            if (parts.Length == 2)
            {
                var key = parts[0];
                var path = parts[1];
                try
                {
                    var secretPath = Path.Combine("/var/openfaas/secrets/", path);
                    if (File.Exists(secretPath))
                    {
                        Secrets[key] = File.ReadAllText(secretPath).Trim();
                        Log("Loaded secret", new { secret_name = key });
                    }
                }
                catch (Exception ex)
                {
                    LogError("Error reading secret file", new { filename = path, error = ex.Message, error_type = ex.GetType().Name });
                }
            }
        }
    }

    /// <summary>
    /// Log with automatic context enrichment and trace correlation.
    /// </summary>
    public void Log(string message, object? attributes = null)
    {
        LogInternal(LogLevel.Information, message, "operation", attributes);
    }

    /// <summary>
    /// Log an error with automatic context enrichment and trace correlation.
    /// </summary>
    public void LogError(string message, object? attributes = null)
    {
        LogInternal(LogLevel.Error, message, "error", attributes);
    }

    /// <summary>
    /// Log a warning with automatic context enrichment and trace correlation.
    /// </summary>
    public void LogWarning(string message, object? attributes = null)
    {
        LogInternal(LogLevel.Warning, message, "operation", attributes);
    }

    /// <summary>
    /// Log debug information with automatic context enrichment and trace correlation.
    /// </summary>
    public void LogDebug(string message, object? attributes = null)
    {
        LogInternal(LogLevel.Debug, message, "operation", attributes);
    }

    private void LogInternal(LogLevel level, string message, string eventType, object? attributes)
    {
        // Get current trace context for correlation
        var activity = Activity.Current;
        var traceId = activity?.TraceId.ToString();
        var spanId = activity?.SpanId.ToString();

        // Build state dictionary with context enrichment
        var state = new Dictionary<string, object?>
        {
            ["service"] = _serviceName,
            ["event_type"] = eventType,
            ["trace_id"] = traceId,
            ["span_id"] = spanId,
            ["scan_id"] = ScanId,
            ["scan_execution_id"] = ScanExecutionId != Guid.Empty ? ScanExecutionId.ToString() : null,
            ["sync_id"] = SyncId,
            ["sync_execution_id"] = SyncExecutionId != Guid.Empty ? SyncExecutionId.ToString() : null,
            ["function_type"] = FunctionType
        };

        // Add custom attributes
        if (attributes != null)
        {
            var props = attributes.GetType().GetProperties();
            foreach (var prop in props)
            {
                state[prop.Name] = prop.GetValue(attributes);
            }
        }

        // Remove null values
        var filteredState = state.Where(kvp => kvp.Value != null).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        // Log using ILogger which will be exported via OpenTelemetry
        using (_logger.BeginScope(filteredState))
        {
            _logger.Log(level, "{Message}", message);
        }
    }

    public FunctionResponse TestConnectionSuccessResponse()
    {
        return new FunctionResponse
        {
            StatusCode = 200,
            Body = new Dictionary<string, object>()
        };
    }

    public FunctionResponse ErrorResponse(bool clientError, string errorMessage)
    {
        var statusCode = clientError ? 400 : 500;
        LogError(errorMessage, new { statusCode });

        return new FunctionResponse
        {
            StatusCode = statusCode,
            Body = new Dictionary<string, object>
            {
                ["error"] = errorMessage
            }
        };
    }

    /// <summary>
    /// Get headers with trace context propagation for calling other services.
    /// This ensures the current trace/span is propagated to downstream services.
    ///
    /// Note: When using HttpClient with OpenTelemetry instrumentation (AddHttpClientInstrumentation),
    /// trace context is automatically propagated. This method is provided for manual header injection
    /// if needed for non-HttpClient scenarios.
    /// </summary>
    /// <returns>Dictionary of headers with trace context (traceparent, tracestate) and caller attributes</returns>
    public Dictionary<string, string> GetPropagationHeaders()
    {
        var headers = new Dictionary<string, string>
        {
            ["Scan-Id"] = CallerAttributes.TryGetValue("scan_id", out var scanId) ? scanId : "",
            ["Scan-Execution-Id"] = CallerAttributes.TryGetValue("scan_execution_id", out var scanExecId) ? scanExecId : ""
        };

        // Get current activity for trace context
        var activity = Activity.Current;
        if (activity != null)
        {
            // Inject W3C trace context headers
            // Format: traceparent: 00-{trace-id}-{span-id}-{trace-flags}
            var traceParent = $"00-{activity.TraceId}-{activity.SpanId}-{(activity.ActivityTraceFlags & ActivityTraceFlags.Recorded) switch { ActivityTraceFlags.Recorded => "01", _ => "00" }}";
            headers["traceparent"] = traceParent;

            // Add tracestate if present
            if (!string.IsNullOrEmpty(activity.TraceStateString))
            {
                headers["tracestate"] = activity.TraceStateString;
            }
        }

        return headers;
    }
}