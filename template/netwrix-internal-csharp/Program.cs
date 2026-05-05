// Copyright (c) OpenFaaS Ltd 2024. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using function;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace function
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var configuration = builder.Configuration;

            // Configure OpenTelemetry
            var serviceName = Environment.GetEnvironmentVariable("SERVICE_NAME") ?? "netwrix-internal-csharp";
            var otelEnabled = Environment.GetEnvironmentVariable("OTEL_ENABLED")?.ToLowerInvariant() != "false";
            var otelEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")
                ?? "http://otel-collector.access-analyzer.svc.cluster.local:4318";
            var environment = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "development";

            // Create ActivitySource for manual instrumentation
            var activitySource = new ActivitySource(serviceName);

            if (otelEnabled)
            {
                var resourceBuilder = ResourceBuilder.CreateDefault()
                    .AddService(serviceName: serviceName, serviceNamespace: "dspm-connectors")
                    .AddAttributes(new Dictionary<string, object>
                    {
                        ["deployment.environment"] = environment
                    });

                builder.Services.AddOpenTelemetry()
                    .ConfigureResource(resource => resource
                        .AddService(serviceName: serviceName, serviceNamespace: "dspm-connectors")
                        .AddAttributes(new Dictionary<string, object>
                        {
                            ["deployment.environment"] = environment
                        }))
                    .WithTracing(tracing =>
                    {
                        tracing
                            .AddSource(serviceName)
                            // ASP.NET Core instrumentation automatically:
                            // 1. Extracts trace context from incoming request headers (traceparent, tracestate)
                            // 2. Creates an Activity (span) from the extracted context or starts a new trace
                            // 3. Sets Activity.Current so child spans can be created
                            .AddAspNetCoreInstrumentation(options =>
                            {
                                options.Filter = (httpContext) =>
                                {
                                    // Don't instrument health check endpoints
                                    var path = httpContext.Request.Path.Value;
                                    return path != "/health" && path != "/healthz" && path != "/ready";
                                };
                                // Enable recording of exception details
                                options.RecordException = true;
                            })
                            // HttpClient instrumentation automatically propagates trace context to outgoing requests
                            .AddHttpClientInstrumentation()
                            .AddOtlpExporter(options =>
                            {
                                options.Endpoint = new Uri($"{otelEndpoint}/v1/traces");
                                options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
                            });
                    })
                    .WithMetrics(metrics =>
                    {
                        metrics
                            .AddAspNetCoreInstrumentation()
                            .AddHttpClientInstrumentation()
                            .AddOtlpExporter((exporterOptions, metricReaderOptions) =>
                            {
                                exporterOptions.Endpoint = new Uri($"{otelEndpoint}/v1/metrics");
                                exporterOptions.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
                                metricReaderOptions.PeriodicExportingMetricReaderOptions.ExportIntervalMilliseconds = 60000;
                            });
                    });

                // Configure logging to export to OTLP
                builder.Logging.AddOpenTelemetry(logging =>
                {
                    logging.SetResourceBuilder(resourceBuilder);
                    logging.IncludeScopes = true;
                    logging.IncludeFormattedMessage = true;
                    logging.AddOtlpExporter(options =>
                    {
                        options.Endpoint = new Uri($"{otelEndpoint}/v1/logs");
                        options.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.HttpProtobuf;
                    });
                });
            }
            else
            {
                builder.Logging.AddConsole();
            }

            // Set minimum log level and filter out noisy logs
            var logLevel = Environment.GetEnvironmentVariable("LOG_LEVEL")?.ToUpper() switch
            {
                "DEBUG" => LogLevel.Debug,
                "INFORMATION" => LogLevel.Information,
                "WARNING" => LogLevel.Warning,
                "ERROR" => LogLevel.Error,
                _ => LogLevel.Information
            };
            builder.Logging.SetMinimumLevel(logLevel);

            // Filter out noisy ASP.NET Core infrastructure logs
            builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
            builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
            builder.Logging.AddFilter("Microsoft.AspNetCore.Routing", LogLevel.Warning);
            builder.Logging.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Warning);

            // Allow function-specific logs at configured level (respects LOG_LEVEL env var)
            builder.Logging.AddFilter("function", logLevel);

            // Register ActivitySource for DI
            builder.Services.AddSingleton(activitySource);

            // Register FunctionContext as scoped - it will be created per request
            builder.Services.AddScoped<FunctionContext>(sp =>
            {
                var httpContextAccessor = sp.GetRequiredService<IHttpContextAccessor>();
                var logger = sp.GetRequiredService<ILogger<FunctionContext>>();
                var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
                return new FunctionContext(httpContextAccessor.HttpContext!, logger, loggerFactory);
            });

            builder.Services.AddHttpContextAccessor();

            // Allow the function to configure additional services
            Handler.MapServices(builder.Services);

            var app = builder.Build();

            // Main handler endpoint - allow the function to configure endpoints
            var serviceProvider = app.Services;
            var source = serviceProvider.GetRequiredService<ActivitySource>();
            Handler.MapEndpoints(app, source);

            // Handle graceful shutdown to flush telemetry
            var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
            lifetime.ApplicationStopping.Register(() =>
            {
                // Force flush all telemetry providers
                var tracerProvider = app.Services.GetService<TracerProvider>();
                var meterProvider = app.Services.GetService<MeterProvider>();

                tracerProvider?.ForceFlush();
                meterProvider?.ForceFlush();
            });

            app.Run("http://127.0.0.1:3000");
        }
    }
}
