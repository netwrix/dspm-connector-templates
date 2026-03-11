using System.Reflection;
using System.Text;
using System.Text.Json;
using Netwrix.Overlord.Sdk.Core.Storage;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using StackExchange.Redis;

namespace Netwrix.ConnectorFramework;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var executionMode = Environment.GetEnvironmentVariable("EXECUTION_MODE");

        return executionMode == "job"
            ? await RunJobModeAsync(args)
            : await RunHttpModeAsync(args);
    }

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
        ((IConnectorHandler)Activator.CreateInstance(handlerType)!).MapServices(builder.Services);

        var port = int.Parse(Environment.GetEnvironmentVariable("PORT") ?? "5000", System.Globalization.CultureInfo.InvariantCulture);
        builder.WebHost.UseUrls($"http://+:{port}");

        var app = builder.Build();

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

        var host = Host.CreateDefaultBuilder(args)
            .ConfigureLogging(ConfigureLogging)
            .ConfigureServices((_, services) =>
            {
                RegisterOpenTelemetry(services, null, isHttpMode: false);
                RegisterFrameworkServices(services, isHttpMode: false);

                services.AddSingleton(typeof(IConnectorHandler), handlerType);
                // Bootstrap instance (parameterless) used only to register connector services before container build.
                ((IConnectorHandler)Activator.CreateInstance(handlerType)!).MapServices(services);
            })
            .Build();

        await host.StartAsync();

        var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Netwrix.ConnectorFramework.Program");
        int exitCode;
        try
        {
            await using var scope = host.Services.CreateAsyncScope();

            var requestData = BuildJobRequestData();
            // Make the job-mode request data available to scoped services
            scope.ServiceProvider.GetRequiredService<RequestDataHolder>().Data = requestData;

            var context = scope.ServiceProvider.GetRequiredService<FunctionContext>();
            var handlerInstance = scope.ServiceProvider.GetRequiredService<IConnectorHandler>();
            var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();

            var result = await handlerInstance.HandleJobAsync(requestData, context, lifetime.ApplicationStopping);
            await context.FlushTablesAsync();

            Console.WriteLine(JsonSerializer.Serialize(result));
            exitCode = 0;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job failed");
            exitCode = 1;
        }

        await host.StopAsync(); // flushes OTEL BatchSpanProcessor
        return exitCode;
    }

    // ── DI registration ───────────────────────────────────────────────────────

    private static void RegisterFrameworkServices(IServiceCollection services, bool isHttpMode)
    {
        // RequestDataHolder is Scoped — pre-seeded for background scopes (via CreateBackgroundScope)
        // and for job mode (via RunJobModeAsync). HTTP scopes fall through to the HttpContext path.
        services.AddScoped<RequestDataHolder>();

        // Redis — Singleton multiplexer (nullable: null if REDIS_URL is not set)
        var redisUrl = Environment.GetEnvironmentVariable("REDIS_URL");
        if (!string.IsNullOrEmpty(redisUrl))
        {
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var opts = ConfigurationOptions.Parse(redisUrl);
                opts.ConnectTimeout = 2000;
                opts.SyncTimeout = 2000;
                opts.KeepAlive = 60;
                return ConnectionMultiplexer.Connect(opts);
            });
        }
        // If REDIS_URL is not set, IConnectionMultiplexer is not registered.
        // RedisSignalHandler accepts IConnectionMultiplexer? and degrades gracefully.

        services.AddHttpClient();
        services.AddScoped<RedisSignalHandler>(sp => new RedisSignalHandler(
            sp.GetService<IConnectionMultiplexer>(),       // null if REDIS_URL not set
            sp.GetRequiredService<ILogger<RedisSignalHandler>>()));
        // ScanShutdownService is Singleton so all scopes share the same shutdown token.
        // StateManager is Scoped (owns per-scan state) but reads the token from the Singleton.
        services.AddSingleton<ScanShutdownService>();
        services.AddScoped<StateManager>();

        // FunctionContext depends on ConnectorRequestData (scoped)
        services.AddScoped<FunctionContext>();
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
                ScanId: http.Request.Headers["Scan-Id"].FirstOrDefault()
                         ?? Environment.GetEnvironmentVariable("SCAN_ID"),
                ScanExecutionId: http.Request.Headers["Scan-Execution-Id"].FirstOrDefault()
                                  ?? Environment.GetEnvironmentVariable("SCAN_EXECUTION_ID"));
        });
    }

    private static void RegisterOpenTelemetry(
        IServiceCollection services,
        ILoggingBuilder? loggingBuilder,
        bool isHttpMode)
    {
        if (Environment.GetEnvironmentVariable("OTEL_ENABLED")?.ToLowerInvariant() == "false")
        {
            return;
        }

        var sourceType = Environment.GetEnvironmentVariable("SOURCE_TYPE") ?? "internal";
        var functionType = Environment.GetEnvironmentVariable("FUNCTION_TYPE") ?? "netwrix";
        var serviceName = $"{sourceType}-{functionType}";
        var environment = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "development";
        var otelEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")
                           ?? "http://otel-collector.access-analyzer.svc.cluster.local:4318";

        var resourceBuilder = ResourceBuilder.CreateDefault()
            .AddService(serviceName)
            .AddAttributes(new Dictionary<string, object>
            {
                ["service.namespace"] = "dspm-connectors",
                ["deployment.environment"] = environment,
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

                tracing.AddOtlpExporter(o => o.Endpoint = new Uri($"{otelEndpoint}/v1/traces"));
            })
            .WithMetrics(metrics =>
            {
                metrics.SetResourceBuilder(resourceBuilder)
                    .AddHttpClientInstrumentation();

                if (isHttpMode)
                {
                    metrics.AddAspNetCoreInstrumentation();
                }

                metrics.AddOtlpExporter(o => o.Endpoint = new Uri($"{otelEndpoint}/v1/metrics"));
            })
            .WithLogging(logging =>
            {
                logging.SetResourceBuilder(resourceBuilder)
                    .AddOtlpExporter(o => o.Endpoint = new Uri($"{otelEndpoint}/v1/logs"));
            });
    }

    // ── Handler discovery ─────────────────────────────────────────────────────

    private static Type DiscoverHandlerType()
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
                catch { return null; }
            })
            .Where(a => a is not null)
            .Cast<Assembly>()
            .Where(a => a.GetReferencedAssemblies()
                .Any(r => r.Name == frameworkAssembly.GetName().Name))
            .ToList();

        var handlerTypes = candidateAssemblies
            .SelectMany(a => { try { return a.GetTypes(); } catch { return []; } })
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
        var logLevel = Environment.GetEnvironmentVariable("LOG_LEVEL")?.ToUpperInvariant() switch
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

    private static ConnectorRequestData BuildJobRequestData()
    {
        var requestDataJson = Environment.GetEnvironmentVariable("REQUEST_DATA") ?? "{}";
        var body = Encoding.UTF8.GetBytes(requestDataJson);

        return new ConnectorRequestData(
            Method: "POST",
            Path: Environment.GetEnvironmentVariable("REQUEST_PATH") ?? "/connector/test_connection",
            Headers: new Dictionary<string, string>(),
            Body: body,
            ScanId: Environment.GetEnvironmentVariable("SCAN_ID"),
            ScanExecutionId: Environment.GetEnvironmentVariable("SCAN_EXECUTION_ID"));
    }
}
