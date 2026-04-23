using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Http;
using Netwrix.Overlord.Sdk.Core.Crawling;
using Netwrix.Overlord.Sdk.Core.Storage;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using StackExchange.Redis;

namespace Netwrix.ConnectorFramework;

internal static class Program
{
    private static readonly ActivitySource ActivitySource = new("Netwrix.ConnectorFramework");

    private const string SecretsBasePath = "/var/secrets";

    private static string SanitizeForLog(string? value) =>
        (value ?? string.Empty).Replace("\r", string.Empty).Replace("\n", string.Empty);

    public static async Task<int> Main(string[] args)
    {
        return IsJobMode()
            ? await RunJobModeAsync(args)
            : await RunHttpModeAsync(args);
    }

    internal static bool IsJobMode() =>
        Environment.GetEnvironmentVariable(EnvironmentVariables.ExecutionMode) == "job" ||
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(EnvironmentVariables.RequestData));

    // ── HTTP mode ─────────────────────────────────────────────────────────────

    private static async Task<int> RunHttpModeAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureLogging(builder.Logging);
        RegisterOpenTelemetry(builder.Services, builder.Logging, isHttpMode: true);
        RegisterFrameworkServices(builder.Services, isHttpMode: true);

        var handlerType = DiscoverHandlerType();
        builder.Services.AddSingleton(typeof(IConnectorHandler), handlerType);
        // Bootstrap instance (parameterless) used only to register connector services before container build.
        // The DI-resolved singleton is used for all request handling.
        ((IConnectorHandler)Activator.CreateInstance(handlerType)!).MapServices(builder.Services, builder.Configuration);

        var portStr = Environment.GetEnvironmentVariable(EnvironmentVariables.Port) ?? "5000";
        if (!int.TryParse(portStr, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var port))
        {
            throw new InvalidOperationException(
                $"PORT environment variable '{portStr}' is not a valid port number.");
        }
        builder.WebHost.UseUrls($"http://+:{port}");

        var app = builder.Build();

        var requestLogger = app.Services
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("Netwrix.ConnectorFramework.Program");

        if (!ValidateSecretMappings(Environment.GetEnvironmentVariable(EnvironmentVariables.SecretMappings), requestLogger))
        {
            return 1;
        }

        app.Use(async (ctx, next) =>
        {
            using var activity = ActivitySource.StartActivity("process_request");
            requestLogger.LogInformation(
                "Received request {Method} {Path}",
                SanitizeForLog(ctx.Request.Method), SanitizeForLog(ctx.Request.Path.Value));
            try
            {
                await next(ctx);
                activity?.SetStatus(ActivityStatusCode.Ok);
                requestLogger.LogInformation(
                    "Request completed {StatusCode}",
                    ctx.Response.StatusCode);
            }
            catch (Exception ex)
            {
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                activity?.RecordException(ex);
                requestLogger.LogError(ex,
                    "Request failed {Method} {Path}",
                    SanitizeForLog(ctx.Request.Method), SanitizeForLog(ctx.Request.Path.Value));
                throw;
            }
        });

        // Enable buffering and eagerly read the body so the DI factory can access it synchronously.
        app.Use(async (ctx, next) =>
        {
            ctx.Request.EnableBuffering();
            ctx.Items["_body"] = await ReadBodyBytesAsync(ctx.Request);
            await next(ctx);
        });

        app.Services.GetRequiredService<IConnectorHandler>().MapEndpoints(app);
        app.MapGet("/health", () => Results.Ok());

        await app.RunAsync();
        return 0;
    }

    // ── Job mode ──────────────────────────────────────────────────────────────

    private static async Task<int> RunJobModeAsync(string[] args)
    {
        var handlerType = DiscoverHandlerType();

        using var host = Host.CreateDefaultBuilder(args)
            .ConfigureLogging(ConfigureLogging)
            .ConfigureServices((ctx, services) =>
            {
                RegisterOpenTelemetry(services, null, isHttpMode: false);
                RegisterFrameworkServices(services, isHttpMode: false);

                services.AddSingleton(typeof(IConnectorHandler), handlerType);
                // Bootstrap instance (parameterless) used only to register connector services before container build.
                ((IConnectorHandler)Activator.CreateInstance(handlerType)!).MapServices(services, ctx.Configuration);
            })
            .Build();

        await host.StartAsync();

        var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Netwrix.ConnectorFramework.Program");

        if (!ValidateSecretMappings(Environment.GetEnvironmentVariable(EnvironmentVariables.SecretMappings), logger))
        {
            return 1;
        }

        int exitCode;
        Activity? jobActivity = null;
        FunctionContext? context = null;
        var isLongRunning = false;
        var executionStopwatch = Stopwatch.StartNew();
        try
        {
            await using var scope = host.Services.CreateAsyncScope();

            jobActivity = ActivitySource.StartActivity("job_execution");

            var requestData = BuildJobRequestData();
            // Make the job-mode request data available to scoped services
            scope.ServiceProvider.GetRequiredService<RequestDataHolder>().Data = requestData;

            context = scope.ServiceProvider.GetRequiredService<FunctionContext>();
            var handlerInstance = scope.ServiceProvider.GetRequiredService<IConnectorHandler>();
            var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();

            lifetime.ApplicationStopping.Register(() =>
                logger.LogWarning("SIGTERM received — ApplicationStopping triggered; job will be cancelled"));

            isLongRunning = requestData.Execution.IsLongRunning;

            using (logger.BeginScope(new Dictionary<string, object?>
            {
                ["scan_id"] = requestData.Execution.ScanId,
                ["scan_execution_id"] = requestData.Execution.ScanExecutionId,
                ["function_type"] = requestData.Execution.FunctionType,
                ["source_type"] = requestData.Execution.SourceType,
                ["source_id"] = requestData.Execution.SourceId,
            }))
            {
                logger.LogInformation(
                    "Starting job execution executionMode=job functionType={FunctionType} scanId={ScanId} scanExecutionId={ScanExecutionId}",
                    requestData.Execution.FunctionType,
                    requestData.Execution.ScanId,
                    requestData.Execution.ScanExecutionId);

                if (isLongRunning)
                {
                    await context.UpdateExecutionAsync(status: ScanStatus.Running);
                }

                object result;
                using (var handleActivity = ActivitySource.StartActivity("handle_request"))
                {
                    result = await handlerInstance.HandleJobAsync(requestData, context, lifetime.ApplicationStopping);
                }
                await context.FlushTablesAsync();

                // Write the result JSON to stdout so connector-api can capture it as logs.
                var resultJson = JsonSerializer.Serialize(result);
                Console.WriteLine(resultJson);

                exitCode = DeriveExitCode(resultJson);

                var metricStatus = exitCode == 0 ? "succeeded" : "failed";
                ConnectorMetrics.ExecutionDuration.Record(
                    executionStopwatch.Elapsed.TotalSeconds,
                    new KeyValuePair<string, object?>("status", metricStatus));

                if (exitCode == 0)
                {
                    jobActivity?.SetStatus(ActivityStatusCode.Ok);
                }
                else
                {
                    jobActivity?.SetStatus(ActivityStatusCode.Error, "Handler returned error statusCode");
                }
            }
        }
        catch (Exception ex)
        {
            ConnectorMetrics.ExecutionDuration.Record(
                executionStopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("status", "failed"));

            jobActivity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            jobActivity?.RecordException(ex);
            logger.LogError(ex, "Job failed");
            if (isLongRunning && context is not null)
            {
                await context.UpdateExecutionAsync(status: ScanStatus.Failed, completedAt: DateTimeOffset.UtcNow);
            }

            exitCode = 1;
        }
        finally
        {
            jobActivity?.Dispose();
        }

        await host.StopAsync();
        // host.Dispose() called here by using — triggers OpenTelemetryLoggerProvider.Dispose() → ForceFlush()
        return exitCode;
    }

    // ── DI registration ───────────────────────────────────────────────────────

    private static void RegisterFrameworkServices(IServiceCollection services, bool isHttpMode)
    {
        // RequestDataHolder is Scoped — pre-seeded for background scopes (via CreateBackgroundScope)
        // and for job mode (via RunJobModeAsync). HTTP scopes fall through to the HttpContext path.
        services.AddScoped<RequestDataHolder>();

        // Redis — Singleton multiplexer (nullable: null if REDIS_URL is not set)
        var redisUrl = Environment.GetEnvironmentVariable(EnvironmentVariables.RedisUrl);
        if (!string.IsNullOrEmpty(redisUrl))
        {
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                // ConfigurationOptions.Parse() does not handle redis:// URIs correctly —
                // it treats the full URI string (including scheme and /db path) as the
                // hostname, which breaks DNS. Parse redis:// URIs manually.
                ConfigurationOptions opts;
                if (Uri.TryCreate(redisUrl, UriKind.Absolute, out var uri)
                    && uri.Scheme is "redis" or "rediss")
                {
                    opts = new ConfigurationOptions();
                    opts.EndPoints.Add(uri.Host, uri.Port > 0 ? uri.Port : 6379);
                    if (uri.AbsolutePath.TrimStart('/') is { Length: > 0 } dbStr
                        && int.TryParse(dbStr, out var db))
                    {
                        opts.DefaultDatabase = db;
                    }

                    var userInfo = uri.UserInfo;
                    if (!string.IsNullOrEmpty(userInfo))
                    {
                        opts.Password = userInfo.Contains(':') ? userInfo[(userInfo.IndexOf(':') + 1)..] : userInfo;
                    }

                    if (uri.Scheme == "rediss")
                    {
                        opts.Ssl = true;
                    }
                }
                else
                {
                    opts = ConfigurationOptions.Parse(redisUrl);
                }
                opts.AbortOnConnectFail = false;
                opts.ConnectTimeout = 2000;
                opts.SyncTimeout = 2000;
                opts.KeepAlive = 60;
                return ConnectionMultiplexer.Connect(opts);
            });
        }
        // If REDIS_URL is not set, IConnectionMultiplexer is not registered.
        // RedisSignalHandler accepts IConnectionMultiplexer? and degrades gracefully.

        services.AddHttpClient();
        services.AddHttpClient<ConnectorStateClient>(ConnectorStateClient.HttpClientName, client =>
        {
            var url = ServiceUrlHelper.Resolve("CONNECTOR_STATE_FUNCTION", "connector-state");
            client.BaseAddress = new Uri(url.TrimEnd('/') + "/");
            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "Function-Type",
                Environment.GetEnvironmentVariable("FUNCTION_TYPE") ?? "netwrix");
        })
        .AddStandardResilienceHandler(o =>
        {
            // Raise the circuit-breaker threshold: an open circuit during a pause-snapshot write
            // is worse than a transient failure — it suppresses all retries for the sampling window.
            o.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
            o.CircuitBreaker.MinimumThroughput = 10;
        });

        services.AddHttpClient(ServiceNames.DataIngestion)
            .AddStandardResilienceHandler();

        services.AddHttpClient(ServiceNames.UpdateExecution)
            .AddStandardResilienceHandler();

        services.AddHttpClient(ServiceNames.AppDataQuery)
            .AddStandardResilienceHandler();

        // Apply rate-limit tracking to every named HttpClient (including connector-developer clients).
        services.ConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(
                b => b.AdditionalHandlers.Add(new RateLimitTrackingHandler())));
        services.AddScoped<RedisSignalHandler>(sp => new RedisSignalHandler(
            sp.GetService<IConnectionMultiplexer>(),       // null if REDIS_URL not set
            sp.GetRequiredService<ILogger<RedisSignalHandler>>()));
        // Singleton: CrawlRunOrchestrator (singleton) resolves ICrawlRunSignalSource from the root
        // IServiceProvider at construction time. A scoped registration would cause a captive-dependency
        // error in development (ValidateScopes=true). The signal source gets a dedicated
        // RedisSignalHandler so its _lastMessageId offset is independent of the scoped handlers
        // used by StateManager.
        services.AddSingleton<ICrawlRunSignalSource>(sp =>
            new AA26CrawlRunSignalSource(new RedisSignalHandler(
                sp.GetService<IConnectionMultiplexer>(),
                sp.GetRequiredService<ILogger<RedisSignalHandler>>())));

        // ScanShutdownService is Singleton so all scopes share the same shutdown token.
        // StateManager is Scoped (owns per-scan state) but reads the token from the Singleton.
        services.AddSingleton<ScanShutdownService>();
        services.AddScoped<StateManager>();

        // FunctionContext depends on ConnectorRequestData (scoped)
        services.AddScoped<FunctionContext>();
        services.AddScoped<IScanWriter>(sp => sp.GetRequiredService<FunctionContext>());
        services.AddScoped<IScanProgress>(sp => sp.GetRequiredService<FunctionContext>());
        services.AddScoped<IStateStorage, ConnectorStateStorage>();

        if (isHttpMode)
        {
            services.AddHttpContextAccessor();
        }

        services.AddScoped<ConnectorRequestData>(sp =>
        {
            // Background scopes (Task.Run) and job mode pre-seed this holder via
            // CreateBackgroundScope() or RunJobModeAsync() respectively.
            var holder = sp.GetRequiredService<RequestDataHolder>();
            if (holder.IsSet)
            {
                return holder.Data;
            }

            var http = sp.GetService<IHttpContextAccessor>()?.HttpContext;
            if (http is null)
            {
                throw new InvalidOperationException(
                    "ConnectorRequestData cannot be resolved outside of an HTTP request context. " +
                    "Use IServiceScopeFactory.CreateBackgroundScope(requestData) for background scopes.");
            }

            // Body was pre-read by the middleware into HttpContext.Items to avoid sync I/O in the factory.
            var body = http.Items["_body"] as byte[];

            return new ConnectorRequestData(
                Method: http.Request.Method,
                Path: http.Request.Path.Value ?? "/",
                Headers: http.Request.Headers
                    .Where(h => h.Value.Count > 0)
                    .ToDictionary(h => h.Key, h => h.Value.FirstOrDefault() ?? "", StringComparer.OrdinalIgnoreCase),
                Body: body,
                Execution: new ExecutionContext(
                    ScanId: http.Request.Headers["Scan-Id"].FirstOrDefault()
                                      ?? Environment.GetEnvironmentVariable(EnvironmentVariables.ScanId),
                    ScanExecutionId: http.Request.Headers["Scan-Execution-Id"].FirstOrDefault()
                                      ?? Environment.GetEnvironmentVariable(EnvironmentVariables.ScanExecutionId),
                    SourceId: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceId),
                    SourceType: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceType),
                    SourceVersion: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceVersion),
                    FunctionType: Environment.GetEnvironmentVariable(EnvironmentVariables.FunctionType)));
        });
    }

    private static void RegisterOpenTelemetry(
        IServiceCollection services,
        ILoggingBuilder? _,
        bool isHttpMode)
    {
        if (Environment.GetEnvironmentVariable(EnvironmentVariables.OtelEnabled)?.ToLowerInvariant() == "false")
        {
            return;
        }

        var sourceType = Environment.GetEnvironmentVariable(EnvironmentVariables.SourceType) ?? "internal";
        var functionType = Environment.GetEnvironmentVariable(EnvironmentVariables.FunctionType) ?? "netwrix";
        var serviceName = $"{sourceType}-{functionType}";
        var environment = Environment.GetEnvironmentVariable(EnvironmentVariables.Environment) ?? "development";
        // Default matches the Python template (index.py:118) and the in-cluster collector address.
        // Connector authors running outside this cluster should set OTEL_EXPORTER_OTLP_ENDPOINT
        // explicitly; leaving it unset will silently fail to export rather than error.
        var otelEndpoint = Environment.GetEnvironmentVariable(EnvironmentVariables.OtelExporterOtlpEndpoint)
                           ?? "http://otel-collector.access-analyzer.svc.cluster.local:4318";

        var resourceBuilder = ResourceBuilder.CreateDefault()
            .AddService(serviceName)
            .AddAttributes(new Dictionary<string, object>
            {
                ["service.namespace"] = "dspm-connectors",
                ["deployment.environment"] = environment,
                ["service.version"] = Environment.GetEnvironmentVariable(EnvironmentVariables.ImageVersion) ?? "unknown",
                // Execution context — allows Prometheus to correlate all metrics from
                // this connector process with a specific scan execution.
                ["scan_execution_id"] = Environment.GetEnvironmentVariable(EnvironmentVariables.ScanExecutionId) ?? "",
                ["scan_id"] = Environment.GetEnvironmentVariable(EnvironmentVariables.ScanId) ?? "",
                ["source_id"] = Environment.GetEnvironmentVariable(EnvironmentVariables.SourceId) ?? "",
            });

        services.AddOpenTelemetry()
            .WithTracing(tracing =>
            {
                tracing.SetResourceBuilder(resourceBuilder)
                    .AddSource("Netwrix.ConnectorFramework")
                    .AddHttpClientInstrumentation();

                if (isHttpMode)
                {
                    tracing.AddAspNetCoreInstrumentation();
                }

                tracing.AddOtlpExporter(o =>
                {
                    o.Endpoint = new Uri($"{otelEndpoint}/v1/traces");
                    o.Protocol = OtlpExportProtocol.HttpProtobuf;
                });
            })
            .WithMetrics(metrics =>
            {
                metrics.SetResourceBuilder(resourceBuilder)
                    .AddMeter(ConnectorMetrics.MeterName)
                    .AddHttpClientInstrumentation();

                if (isHttpMode)
                {
                    metrics.AddAspNetCoreInstrumentation();
                }

                metrics.AddOtlpExporter(
                    (o, readerOptions) =>
                    {
                        o.Endpoint = new Uri($"{otelEndpoint}/v1/metrics");
                        o.Protocol = OtlpExportProtocol.HttpProtobuf;
                        // Export every 15 s so short-lived job-mode connectors produce
                        // enough data points for timeseries graphs (default is 60 s).
                        readerOptions.PeriodicExportingMetricReaderOptions.ExportIntervalMilliseconds = 15_000;
                    });
            })
            .WithLogging(
                logging =>
                {
                    logging.SetResourceBuilder(resourceBuilder)
                        .AddOtlpExporter(o =>
                        {
                            o.Endpoint = new Uri($"{otelEndpoint}/v1/logs");
                            o.Protocol = OtlpExportProtocol.HttpProtobuf;
                        });
                },
                options =>
                {
                    options.IncludeFormattedMessage = true;  // populate Body in ClickHouse
                    options.IncludeScopes = true;            // capture BeginScope() values as attributes
                    options.ParseStateValues = true;         // capture {ScanId} etc. as structured attributes
                });
    }

    // ── Handler discovery ─────────────────────────────────────────────────────

    internal static Type DiscoverHandlerType()
    {
        // The function assembly sits in the same directory as ConnectorFramework.dll.
        // It is the single assembly (other than ConnectorFramework itself) that references this assembly.
        var frameworkAssembly = typeof(IConnectorHandler).Assembly;
        var frameworkDir = Path.GetDirectoryName(frameworkAssembly.Location)
                           ?? Directory.GetCurrentDirectory();

        var candidateAssemblies = Directory.EnumerateFiles(frameworkDir, "*.dll")
            .Where(f => !Path.GetFileName(f).Equals("ConnectorFramework.dll", StringComparison.OrdinalIgnoreCase))
            .Select(f =>
            {
                try { return Assembly.LoadFrom(f); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[ConnectorFramework] Warning: failed to load assembly '{f}': {ex.Message}");
                    return null;
                }
            })
            .Where(a => a is not null)
            .Cast<Assembly>()
            .Where(a => a.GetReferencedAssemblies()
                .Any(r => r.Name == frameworkAssembly.GetName().Name))
            .ToList();

        var handlerTypes = candidateAssemblies
            .SelectMany(a =>
            {
                try { return a.GetTypes(); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[ConnectorFramework] Warning: failed to enumerate types in '{a.FullName}': {ex.Message}");
                    return [];
                }
            })
            .Where(t => !t.IsAbstract && !t.IsInterface && typeof(IConnectorHandler).IsAssignableFrom(t))
            .ToList();

        return handlerTypes.Count switch
        {
            0 => throw new InvalidOperationException(
                "No IConnectorHandler implementation found. Ensure the function assembly is in the same directory as ConnectorFramework.dll."),
            > 1 => throw new InvalidOperationException(
                $"Multiple IConnectorHandler implementations found: {string.Join(", ", handlerTypes.Select(t => t.FullName))}. Only one is allowed."),
            _ => handlerTypes[0],
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void ConfigureLogging(ILoggingBuilder logging)
    {
        logging.ClearProviders();
        logging.AddConsole();
        var logLevel = Environment.GetEnvironmentVariable(EnvironmentVariables.LogLevel)?.ToUpperInvariant() switch
        {
            "DEBUG" => LogLevel.Debug,
            "WARNING" or "WARN" => LogLevel.Warning,
            "ERROR" => LogLevel.Error,
            _ => LogLevel.Information,
        };
        logging.SetMinimumLevel(logLevel);
    }

    private static async Task<byte[]> ReadBodyBytesAsync(HttpRequest request)
    {
        // EnableBuffering() was already called by the caller before invoking this method.
        request.Body.Position = 0;
        using var ms = new MemoryStream();
        await request.Body.CopyToAsync(ms);
        request.Body.Position = 0;
        return ms.ToArray();
    }

    /// <summary>
    /// Derives the process exit code from the serialized result JSON returned by a connector handler.
    /// Handlers signal failure by returning <see cref="FunctionContext.ErrorResponse"/>, which sets
    /// <c>statusCode</c> to 400 (client error) or 500 (server error). Without this check the process
    /// would always exit 0, causing connector-api — which evaluates job success solely via pod exit code
    /// — to report a completed job even when the connector detected an error (e.g. the SPO connector
    /// catching an Azure AD or certificate exception and returning ValidationResult.Error).
    /// Returns 1 when <c>statusCode</c> ≥ 400, 0 otherwise (including when the field is absent).
    /// </summary>
    internal static int DeriveExitCode(string resultJson)
    {
        using var doc = JsonDocument.Parse(resultJson);
        return doc.RootElement.TryGetProperty("statusCode", out var statusCodeEl)
            && statusCodeEl.GetInt32() >= 400 ? 1 : 0;
    }

    internal static string BuildRequestPath()
    {
        var functionType = Environment.GetEnvironmentVariable(EnvironmentVariables.FunctionType);
        var derivedPath = functionType != null
            ? $"/connector/{functionType.Replace("-", "_", StringComparison.Ordinal)}"
            : "/connector/test_connection";
        return Environment.GetEnvironmentVariable(EnvironmentVariables.RequestPath) ?? derivedPath;
    }

    private static ConnectorRequestData BuildJobRequestData()
    {
        var requestDataJson = Environment.GetEnvironmentVariable(EnvironmentVariables.RequestData) ?? "{}";
        var body = Encoding.UTF8.GetBytes(requestDataJson);

        return new ConnectorRequestData(
            Method: "POST",
            Path: BuildRequestPath(),
            Headers: new Dictionary<string, string>(),
            Body: body,
            Execution: new ExecutionContext(
                ScanId: Environment.GetEnvironmentVariable(EnvironmentVariables.ScanId),
                ScanExecutionId: Environment.GetEnvironmentVariable(EnvironmentVariables.ScanExecutionId),
                SourceId: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceId),
                SourceType: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceType),
                SourceVersion: Environment.GetEnvironmentVariable(EnvironmentVariables.SourceVersion),
                FunctionType: Environment.GetEnvironmentVariable(EnvironmentVariables.FunctionType)));
    }

    /// <summary>
    /// Parses and validates the SECRET_MAPPINGS environment variable at startup.
    /// Returns true if valid (or absent); returns false and logs a critical error if malformed
    /// or if any entry attempts path traversal.
    /// </summary>
    internal static bool ValidateSecretMappings(string? mappings, ILogger logger)
    {
        if (string.IsNullOrEmpty(mappings))
        {
            return true;
        }

        foreach (var entry in mappings.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = entry.Trim();
            var parts = trimmed.Split(':', 2);
            if (parts.Length != 2)
            {
                logger.LogCritical(
                    "SECRET_MAPPINGS entry '{Entry}' is malformed: expected 'aliasKey:secretName' format",
                    trimmed);
                return false;
            }

            var aliasKey = parts[0].Trim();
            var secretName = parts[1].Trim();

            if (string.IsNullOrEmpty(aliasKey))
            {
                logger.LogCritical(
                    "SECRET_MAPPINGS entry '{Entry}' has an empty alias key", trimmed);
                return false;
            }

            if (string.IsNullOrEmpty(secretName))
            {
                logger.LogCritical(
                    "SECRET_MAPPINGS entry '{Entry}' has an empty secret name", trimmed);
                return false;
            }

            // Path traversal guard: secretName must resolve within SecretsBasePath.
            var basePath = Path.GetFullPath(SecretsBasePath);
            var resolvedPath = Path.GetFullPath(Path.Combine(basePath, secretName));
            if (!resolvedPath.StartsWith(basePath + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                logger.LogCritical(
                    "SECRET_MAPPINGS entry '{Entry}': secret name '{SecretName}' contains a path traversal attempt",
                    trimmed, secretName);
                return false;
            }

            logger.LogDebug(
                "SECRET_MAPPINGS: alias '{AliasKey}' maps to secret '{SecretName}'",
                aliasKey, secretName);
        }

        return true;
    }
}
