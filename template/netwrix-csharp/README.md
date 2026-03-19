# Netwrix C# Connector Template

## Overview

This template provides the scaffolding for a Netwrix DSPM connector written in C#. The repository is split into two parts:

- **`ConnectorFramework/`** — Shared framework code that is copied unchanged into every connector. Contains the per-request context, batch management, state storage, signal handling, and SDK facade adapters. Do not modify this directory in your connector project.
- **`function/`** — Per-connector implementation. Implement your connector operations in `Handler.cs`. Add connector-specific NuGet packages to `function/Function.csproj` only.

The connector runs in two modes:

- **HTTP mode** (default) — an ASP.NET Core minimal-API server. Operations like `test_connection` return directly; long-running scans return `202 Accepted` and execute in the background via `IServiceScopeFactory`.
- **Job mode** (`EXECUTION_MODE=job`) — a single invocation that runs, writes results, then exits. Used by container-based job schedulers.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  SDK Contract (Netwrix.Overlord.Sdk.Cloud)           │
│  ICorePlatformFacade · ICrawlTaskManagementPlatformFacade │
└───────────────────────┬──────────────────────────────┘
                        │ implemented by
┌───────────────────────▼──────────────────────────────┐
│  Facade Adapters (ConnectorFramework/)               │
│  AACorePlatformFacade          → depends on IScanWriter   │
│  AACrawlTaskCorePlatformFacade → depends on IScanWriter   │
│                                  + IScanProgress      │
└───────────────────────┬──────────────────────────────┘
                        │ implemented by
┌───────────────────────▼──────────────────────────────┐
│  Framework Infrastructure (ConnectorFramework/)      │
│  FunctionContext (scoped) — implements IScanWriter    │
│                              and IScanProgress        │
│    • BatchManager — HTTP batching to data-ingestion   │
│    • IStateStorage / ConnectorStateStorage            │
│    • UpdateExecutionAsync — progress reporting        │
│    • GetPriorExecutionAsync — prior execution lookup  │
│    • StartActivity — OpenTelemetry spans              │
│    • Secrets — /var/secrets lazy loader               │
│    • Log — structured logger with scan-context scope  │
│  StateManager (scoped) — pause/stop FSM              │
│    • SupportedStates — declares stop/pause capability │
│    • OnStateChange — transition callbacks             │
│  RedisSignalHandler — Redis stream signal polling     │
│  ScanShutdownService (singleton) — app lifetime       │
│  ExecutionContext — immutable scan metadata           │
│  ScanStatus — terminal/intermediate status constants  │
└──────────────────────────────────────────────────────┘
```

### Key types

| Type | Lifetime | Purpose |
|---|---|---|
| `FunctionContext` | Scoped | Per-request context. Provides `IScanWriter`, `IScanProgress`, secrets, state, telemetry. |
| `IScanWriter` | Scoped (alias of `FunctionContext`) | Write objects and flush batches. Inject into facades that buffer scan output. |
| `IScanProgress` | Scoped (alias of `FunctionContext`) | Report progress and emit OTel spans. Inject into facades that track execution progress. |
| `ExecutionContext` | Immutable record | Scan metadata (`ScanId`, `ScanExecutionId`, `SourceId`, `SourceType`, `FunctionType`, `SourceVersion`). Exposed as `ctx.Execution`. |
| `ScanStatus` | Static constants | String constants for all scan states (`Running`, `Completed`, `Failed`, `Stopped`, `Paused`, …). Use instead of raw strings. |
| `PriorExecution` | Immutable record | Result of `GetPriorExecutionAsync` — holds `Id`, `Status`, `CompletedObjects` from a previous scan execution. |
| `AACorePlatformFacade` | Scoped | SDK adapter — translates `ICorePlatformFacade` calls into `IScanWriter` operations. |
| `AACrawlTaskCorePlatformFacade` | Scoped | Crawl-task orchestration — delegates `ICorePlatformFacade` methods to `AACorePlatformFacade` and uses `IScanProgress` for progress updates. |
| `StateManager` | Scoped | Pause/stop state machine backed by `RedisSignalHandler`. |
| `SupportedStates` | Record | Declares which control signals this connector handles (`Stop`, `Pause`, `Resume`). Defaults to stop-only. |
| `BatchManager` | Scoped (owned by `FunctionContext`) | Buffers objects and flushes them to the data-ingestion HTTP endpoint in configurable batch sizes. |
| `RedisSignalHandler` | Scoped | Reads control signals (pause, stop) and writes status to Redis streams. |
| `ScanShutdownService` | Singleton | Provides an `ApplicationStopping` token shared across all scopes. |

---

## Execution lifecycle

`ShutdownAsync` updates both Redis and the `app-update-execution` HTTP service. Always call it with a terminal status at the end of every scan path — including catch blocks.

Use `ScanStatus` constants instead of raw strings:

| Constant | Value | When to use |
|---|---|---|
| `ScanStatus.Completed` | `"completed"` | Scan finished successfully. |
| `ScanStatus.Stopped` | `"stopped"` | A STOP signal was received (`ShouldStopAsync` returned `true`). |
| `ScanStatus.Paused` | `"paused"` | A PAUSE signal was received (`ShouldPauseAsync` returned `true`). |
| `ScanStatus.Failed` | `"failed"` | An unhandled exception occurred. |

**Job mode:** the framework auto-sets `"running"` before calling `HandleJobAsync` (for long-running function types) and `"failed"` if an unhandled exception escapes the handler — but handlers should still call `ShutdownAsync` explicitly for proper Redis cleanup. The framework's `"failed"` call is a safety net only.

---

## Two approaches to writing a connector

### Approach A — SDK-driven (crawl task connectors)

> Use when the Netwrix Overlord SDK drives the scan via `ICorePlatformFacade` / `ICrawlTaskManagementPlatformFacade`.

The SDK calls your facade's `UploadSiTRecords`, `UploadSiTSchemaRecords`, and `UploadActivityRecords` methods. The facade handles batching automatically.

**Register in `MapServices()`:**
```csharp
services.AddScoped<AACorePlatformFacade>();
services.AddScoped<AACrawlTaskCorePlatformFacade>();
services.AddScoped<ICrawlTaskManagementPlatformFacade>(
    sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
services.AddScoped<ICrawlTaskCorePlatformFacade>(
    sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
services.AddScoped<ICorePlatformFacade>(
    sp => sp.GetRequiredService<AACrawlTaskCorePlatformFacade>());
```

**Typical scan lifecycle:**
```csharp
facade.Initialize(source, configs);

// SDK drives UploadSiTRecords / UploadSiTSchemaRecords calls internally

await facade.FinalizeScan();
```

Example connector using this approach: `sharepoint-online-ccf`

---

### Approach B — Handler-driven (simple/custom connectors)

> Use when the handler owns the scan loop and writes objects directly without SDK orchestration.

Inject `FunctionContext` (or `IScanWriter`) directly into your endpoint handler.

**Important:** In background `Task.Run` blocks you must use `scopeFactory.CreateBackgroundScope(requestData)` instead of `CreateAsyncScope()` — this pre-seeds the scope with the captured request data so `FunctionContext` resolves correctly outside the HTTP request lifetime.

**Typical scan loop:**
```csharp
app.MapPost("/connector/access_scan", async (
    FunctionContext ctx,
    IServiceScopeFactory scopeFactory,
    CancellationToken kestrelCt) =>
{
    var requestData = ctx.Request; // capture before Task.Run
    _ = Task.Run(async () =>
    {
        await using var scope = scopeFactory.CreateBackgroundScope(requestData);
        var ctx = scope.ServiceProvider.GetRequiredService<FunctionContext>();
        var stateManager = scope.ServiceProvider.GetRequiredService<StateManager>();
        var executionId = ctx.Execution.ScanExecutionId!;

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            kestrelCt, stateManager.Token);
        var ct = linked.Token;

        try
        {
            foreach (var item in GetItems())
            {
                if (await stateManager.ShouldStopAsync(executionId, ct))
                {
                    await stateManager.ShutdownAsync(executionId, ScanStatus.Stopped, ct);
                    return;
                }
                if (await stateManager.ShouldPauseAsync(executionId, ct))
                {
                    await ctx.SetConnectorStateAsync(
                        new Dictionary<string, object?> { ["lastProcessed"] = item.Id }, ct);
                    await stateManager.ShutdownAsync(executionId, ScanStatus.Paused, ct);
                    return;
                }

                ctx.SaveObject("objects", item);
            }

            await ctx.FlushTablesAsync(ct);
            await stateManager.ShutdownAsync(executionId, ScanStatus.Completed, ct);
        }
        catch (Exception)
        {
            await stateManager.ShutdownAsync(executionId, ScanStatus.Failed, ct);
            throw;
        }
    });
    return Results.Accepted();
});
```

Example connector using this approach: `fake-fs`

---

## Key services reference

| Service | Lifetime | Registration |
|---|---|---|
| `FunctionContext` | Scoped | Framework (`Program.cs`) |
| `IScanWriter` | Scoped | Framework — alias of `FunctionContext` |
| `IScanProgress` | Scoped | Framework — alias of `FunctionContext` |
| `IStateStorage` | Scoped | Framework — `ConnectorStateStorage` |
| `StateManager` | Scoped | Framework |
| `RedisSignalHandler` | Scoped | Framework |
| `ScanShutdownService` | Singleton | Framework |
| `AACorePlatformFacade` | Scoped | Connector `Handler.MapServices()` |
| `AACrawlTaskCorePlatformFacade` | Scoped | Connector `Handler.MapServices()` |
| `ICorePlatformFacade` | Scoped | Connector `Handler.MapServices()` |
| `ICrawlTaskManagementPlatformFacade` | Scoped | Connector `Handler.MapServices()` |

---

## `FunctionContext` API reference

| Member | Description |
|---|---|
| `ctx.Execution` | `ExecutionContext` — immutable scan metadata (IDs, source type, function type). |
| `ctx.Log` | Structured `ILogger` automatically scoped with `scan_id`, `scan_execution_id`, `function_type`, and `source_type`. |
| `ctx.Secrets` | Lazy-loaded dictionary of secrets from `/var/secrets/` with `SECRET_MAPPINGS` aliases applied. |
| `ctx.StateStorage` | `IStateStorage` backed by the connector-state service. Prefer the typed methods below for common operations. |
| `ctx.SaveObject(table, obj)` | Buffers an object into the named table's `BatchManager`. |
| `ctx.GetTable(table)` | Returns (or lazily creates) a `BatchManager` for the given table — use when you need direct batch control. |
| `ctx.FlushTablesAsync(ct)` | Flushes all active table buffers to the data-ingestion service. |
| `ctx.UpdateExecutionAsync(...)` | Reports scan progress to the upstream connector-api. |
| `ctx.GetConnectorStateAsync(ct)` | Retrieves all connector state keys for the current scan ID. |
| `ctx.SetConnectorStateAsync(dict, ct)` | Writes a `Dictionary<string, object?>` to the connector-state service. |
| `ctx.DeleteConnectorStateAsync(names, ct)` | Deletes specific keys (or all state if `names` is null). |
| `ctx.GetPriorExecutionAsync(scanExecutionId, ct)` | Queries `app-data-query` for a previous execution by ID. Returns a `PriorExecution` record or null if not found. |
| `ctx.StartActivity(name)` | Starts an OpenTelemetry span. Always use with `using`. |
| `ctx.GetCallerHeaders()` | Returns W3C trace-context and scan-context headers for outbound HTTP calls. |
| `FunctionContext.TestConnectionSuccessResponse()` | Standard `test_connection` success payload. |
| `FunctionContext.ErrorResponse(clientError, message)` | Standard error payload (400 or 500). |

---

## `StateManager` API reference

`StateManager` defaults to supporting only the STOP signal. To enable pause and/or resume, register a custom `SupportedStates` before the framework registers `StateManager`, or pass it via the constructor in tests.

```csharp
// In MapServices() — enable pause support
services.AddScoped(_ => new SupportedStates(Stop: true, Pause: true, Resume: true));
```

| Member | Description |
|---|---|
| `stateManager.Token` | `CancellationToken` cancelled when a STOP signal arrives or `ShutdownAsync` is called. |
| `stateManager.CurrentState` | Current state string (volatile read — safe from any thread). |
| `stateManager.ShouldStopAsync(executionId, ct)` | Polls Redis (throttled to `SignalCheckIntervalSeconds`) and returns `true` if a STOP was received. Returns `false` if `SupportedStates.Stop` is false. |
| `stateManager.ShouldPauseAsync(executionId, ct)` | Like `ShouldStopAsync` but for PAUSE. Returns `false` if `SupportedStates.Pause` is false. |
| `stateManager.ShutdownAsync(executionId, finalStatus, ct)` | Transitions state, calls `UpdateExecutionAsync`, publishes status to Redis, and cancels the token. |
| `stateManager.SetStateAsync(newState, ct)` | Manual state transition — returns `false` if invalid from the current state. |
| `stateManager.OnStateChange(callback)` | Registers an async callback invoked after every successful state transition. |

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `EXECUTION_MODE` | `""` (HTTP) | Set to `job` to run in job mode. |
| `PORT` | `5000` | HTTP listen port (HTTP mode only). |
| `SCAN_ID` | — | Scan identifier injected into `ConnectorRequestData`. |
| `SCAN_EXECUTION_ID` | — | Scan execution identifier for progress reporting. |
| `SOURCE_ID` | — | Source instance identifier. |
| `SOURCE_TYPE` | `internal` | Source type tag. Used in OTel service name and structured logs. |
| `SOURCE_VERSION` | — | Source version tag. |
| `REQUEST_DATA` | `{}` | JSON request body for job mode. |
| `REQUEST_PATH` | derived | Request path for job mode. Derived from `FUNCTION_TYPE` as `/connector/{function_type}` if not explicitly set. |
| `REDIS_URL` | — | Redis connection string. Required for pause/stop signals. |
| `SECRET_MAPPINGS` | — | Comma-separated `appKey:secretFile` alias pairs (e.g. `dbPass:my-db-secret`). |
| `FUNCTION_TYPE` | `netwrix` | OpenTelemetry service name suffix; also added to outbound `Function-Type` header and used to derive `REQUEST_PATH` in job mode. |
| `ENVIRONMENT` | `development` | Deployment environment tag in OTel resource attributes. |
| `OTEL_ENABLED` | `true` | Set to `false` to disable all OpenTelemetry export. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector...` | OTLP collector endpoint. |
| `APP_UPDATE_EXECUTION_FUNCTION` | — | Override URL for the `app-update-execution` service. |
| `APP_DATA_QUERY_FUNCTION` | — | Override URL for the `app-data-query` service. |
| `CONNECTOR_STATE_FUNCTION` | — | Override URL for the `connector-state` service. |
| `LOG_LEVEL` | `Information` | Minimum log level (`DEBUG`, `WARNING`, `ERROR`, `Information`). |
| `RUN_LOCAL` | — | Set to `true` to resolve service URLs as `http://{serviceName}:8080`. |
| `USE_OPENFAAS_GATEWAY` | — | Set to `true` to route service calls through the OpenFaaS gateway. |
| `OPENFAAS_GATEWAY` | `http://gateway.openfaas:8080` | OpenFaaS gateway URL (used when `USE_OPENFAAS_GATEWAY=true`). |
| `COMMON_FUNCTIONS_NAMESPACE` | `access-analyzer` | Kubernetes namespace for in-cluster service DNS resolution. |
