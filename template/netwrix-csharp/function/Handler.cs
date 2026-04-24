using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Netwrix.ConnectorFramework;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;

namespace Netwrix.Connector;

/// <summary>
/// Connector handler stub — implement your operations here.
///
/// HTTP mode: map your routes in MapEndpoints using ASP.NET Core Minimal APIs.
///   - For short-lived operations (test_connection, discovery) return directly.
///   - For long-running scans: return 202 Accepted and run the scan in the background.
///     Use IServiceScopeFactory to create a new scope for the background work.
///
/// Job mode: dispatch on request.Path in HandleJobAsync.
///
/// Add connector-specific NuGet packages in function/Function.csproj only.
/// Do NOT modify ConnectorFramework.csproj.
/// </summary>
public class Handler : IConnectorHandler
{
    /// <summary>
    /// Registers the crawl SDK facades required by every Netwrix SDK connector.
    ///
    /// All four interface aliases resolve to the same scoped instance of
    /// <see cref="AACrawlTaskCorePlatformFacade"/>, preventing the split-state bug where
    /// count dictionaries
    /// diverge across different interface resolutions.
    ///
    /// TODO: add connector-specific services after this block (e.g. SharePoint graph client, options).
    /// </summary>
    public void MapServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<AACorePlatformFacade>();
        services.AddScoped<AACrawlTaskCorePlatformFacade>();
        services.AddScoped<ICrawlTaskManagementPlatformFacade>(
            sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
        services.AddScoped<ICrawlTaskCorePlatformFacade>(
            sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
        services.AddScoped<ICorePlatformFacade>(
            sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/connector/discovery", () => Results.Ok(new
        {
            operations = new[] { "test_connection" },
        }));

        app.MapPost("/connector/test_connection", async (
            FunctionContext ctx,
            CancellationToken ct) => Results.Ok(await TestConnectionAsync(ctx, ct)));
    }

    public Task<object> HandleJobAsync(
        ConnectorRequestData request,
        FunctionContext ctx,
        CancellationToken ct)
        => request.Path switch
        {
            "/connector/test_connection" => TestConnectionAsync(ctx, ct),
            _ => throw new InvalidOperationException($"Unknown job path: {request.Path}"),
        };

    // ── Operations ────────────────────────────────────────────────────────────

    private static async Task<object> TestConnectionAsync(FunctionContext ctx, CancellationToken ct)
    {
        // TODO: implement real connection test using ctx.Secrets["my-secret"]
        await Task.CompletedTask;
        return FunctionContext.TestConnectionSuccessResponse();
    }

    // ── Long-running scan example (uncomment and adapt as needed) ─────────────
    //
    // public void MapEndpoints(WebApplication app)
    // {
    //     app.MapPost("/connector/access_scan", async (
    //         IServiceScopeFactory scopeFactory,
    //         CancellationToken kestrelCt) =>
    //     {
    //         _ = Task.Run(async () =>
    //         {
    //             await using var scope = scopeFactory.CreateAsyncScope();
    //             var ctx = scope.ServiceProvider.GetRequiredService<FunctionContext>();
    //             var stateManager = scope.ServiceProvider.GetRequiredService<StateManager>();
    //
    //             // Link Kestrel shutdown token with Redis STOP signal token
    //             using var linked = CancellationTokenSource.CreateLinkedTokenSource(
    //                 kestrelCt, stateManager.Token);
    //
    //             await RunScanAsync(ctx, stateManager, linked.Token);
    //         });
    //         return Results.Accepted();
    //     });
    // }
    //
    // private static async Task RunScanAsync(
    //     FunctionContext ctx,
    //     StateManager stateManager,
    //     CancellationToken ct)
    // {
    //     var executionId = ctx.Execution.ScanExecutionId ?? throw new InvalidOperationException("ScanExecutionId is required");
    //
    //     try
    //     {
    //         // Example: write scanned objects
    //         var table = ctx.GetTable("my_table");
    //
    //         foreach (var item in GetItems())
    //         {
    //             if (await stateManager.ShouldStopAsync(executionId, ct))
    //             {
    //                 await stateManager.ShutdownAsync(executionId, "stopped", ct);
    //                 return;
    //             }
    //             if (await stateManager.ShouldPauseAsync(executionId, ct))
    //             {
    //                 await ctx.SetConnectorStateAsync(new { lastProcessed = item.Id }, ct);
    //                 await stateManager.ShutdownAsync(executionId, "paused", ct);
    //                 return;
    //             }
    //
    //             table.AddObject(item);
    //         }
    //
    //         await ctx.FlushTablesAsync(ct);
    //         await stateManager.ShutdownAsync(executionId, "completed", ct);
    //     }
    //     catch (Exception)
    //     {
    //         await stateManager.ShutdownAsync(executionId, "failed", ct);
    //         throw;
    //     }
    // }
}
