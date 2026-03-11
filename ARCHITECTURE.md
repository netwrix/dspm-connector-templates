# Architecture Overview

`dspm-connector-templates` provides the runtime scaffolding for all DSPM connector functions. Each template bundles an HTTP server, job-mode runner, OpenTelemetry instrumentation, Redis stop/pause/resume signal handling, and (for connector templates) batched data ingestion. Connector authors implement one file — `handler.py` or `Handler.cs` — and the template handles everything else.

## 1. Project Structure

```
/
├── template/
│   ├── netwrix-python/              # Python connector template
│   │   ├── index.py                 # HTTP server + job-mode entrypoint
│   │   ├── redis_signal_handler.py  # Redis Streams client for control signals
│   │   ├── state_manager.py         # Stop/pause/resume state machine
│   │   ├── pyproject.toml           # Python dependencies (managed by uv)
│   │   ├── Dockerfile               # Multi-stage container image
│   │   └── function/
│   │       └── handler.py           # Connector author implements this
│   ├── netwrix-internal-python/     # Python template for internal functions
│   │   ├── index.py                 # HTTP server + job-mode entrypoint
│   │   ├── pyproject.toml
│   │   ├── Dockerfile
│   │   └── function/
│   │       └── handler.py
│   ├── netwrix-csharp/              # C# connector template
│   │   ├── ConnectorFramework/      # Core runtime library (do not modify)
│   │   │   ├── Program.cs           # HTTP + job-mode bootstrap, handler discovery
│   │   │   ├── FunctionContext.cs   # Per-request DI context (secrets, tables, spans)
│   │   │   ├── IConnectorHandler.cs # Interface connector handlers must implement
│   │   │   ├── BatchManager.cs      # Buffered async data ingestion
│   │   │   ├── StateManager.cs      # Stop/pause/resume state machine
│   │   │   ├── RedisSignalHandler.cs
│   │   │   └── ConnectorRequestData.cs
│   │   ├── ConnectorFramework.Tests/ # Unit tests for the framework
│   │   ├── function/
│   │   │   └── Handler.cs           # Connector author implements IConnectorHandler here
│   │   └── Dockerfile
│   └── netwrix-internal-csharp/     # C# template for internal functions
│       ├── Program.cs               # HTTP server bootstrap
│       ├── FunctionContext.cs       # Simplified context (logging, secrets, OTel)
│       ├── FunctionRequest.cs
│       ├── FunctionResponse.cs
│       └── Dockerfile
├── docs/
│   └── STOP_PAUSE_RESUME_GUIDE.md  # Implementation guide
└── .github/
    └── workflows/
        └── ruff.yml                 # Python lint/format CI
```

## 2. High-Level System Diagram

```mermaid
graph TD
    subgraph "Connector Container (runtime per function)"
        A[HTTP Server / Job Runner<br/>index.py · Program.cs] --> B[handler.py / Handler.cs<br/>connector scan logic]
        B --> C[FunctionContext / Context<br/>secrets · logging · tracing]
        C --> D[BatchManager<br/>500 KB buffer]
        C --> E[StateManager<br/>stop · pause · resume]
        E --> F[RedisSignalHandler]
    end

    subgraph "Platform Services"
        G[data-ingestion service]
        H[Redis Streams<br/>scan:control:{id}<br/>scan:status:{id}]
        I[app-update-execution service]
        J[OTLP Collector<br/>Grafana / OpenTelemetry]
        K[Core API<br/>connector-api]
    end

    D -->|"HTTP POST async<br/>500 KB batches"| G
    F <-->|"control signals<br/>status updates"| H
    C -->|"execution progress"| I
    A -->|"traces / metrics / logs"| J
    K -->|"STOP / PAUSE / RESUME"| H
```

## 3. Core Components

### 3.1. netwrix-python

**Description:** Python connector template for external source and IAM connectors. Runs as a Flask/Waitress HTTP server or a one-shot Kubernetes job, selected by the `EXECUTION_MODE` environment variable. Provides `StateManager` and `RedisSignalHandler` for graceful stop/pause/resume, and a `Context` object with structured logging and OpenTelemetry tracing.

**Technologies:** Python 3.12, Flask, Waitress, Redis, OpenTelemetry SDK, uv

**Key files:** `index.py` (entrypoint), `state_manager.py`, `redis_signal_handler.py`, `function/handler.py` (connector author fills this)

### 3.2. netwrix-internal-python

**Description:** Simplified Python template for internal platform functions (e.g., `data-ingestion`, `regex-match`, `sensitive-data-orchestrator`). Same HTTP/job dual-mode entrypoint as `netwrix-python` but without connector-specific `StateManager` or `BatchManager`. Provides the same `Context`/`ContextLogger` and OpenTelemetry setup.

**Technologies:** Python 3.12, Flask, Waitress, OpenTelemetry SDK, uv

### 3.3. netwrix-csharp

**Description:** C# (.NET 8) connector template with a full `ConnectorFramework` runtime library. At startup, `Program.cs` discovers the connector's `IConnectorHandler` implementation via reflection and registers it in DI. Supports HTTP mode (ASP.NET Core Minimal API, long-running scans run in background scopes) and job mode (single `HandleJobAsync` invocation). `FunctionContext` provides secrets, per-table `BatchManager` instances, checkpoint state via Redis, execution progress reporting, and OpenTelemetry spans. `StateManager` polls Redis for STOP/PAUSE/RESUME signals and exposes a `CancellationToken` that is cancelled on STOP.

**Technologies:** .NET 8, ASP.NET Core, StackExchange.Redis, OpenTelemetry .NET SDK

**Key files:** `ConnectorFramework/Program.cs`, `ConnectorFramework/FunctionContext.cs`, `ConnectorFramework/IConnectorHandler.cs`, `function/Handler.cs` (connector author fills this)

### 3.4. netwrix-internal-csharp

**Description:** C# template for internal platform functions. Provides HTTP server bootstrap and a simplified `FunctionContext` with structured logging and secrets, but no `BatchManager` or `StateManager`. Suited for request/response functions that do not perform long-running scans.

**Technologies:** .NET 8, ASP.NET Core, OpenTelemetry .NET SDK

## 4. Data Stores

### 4.1. Redis

**Type:** Redis Streams
**Purpose:** Control plane for running scan executions. `RedisSignalHandler` reads STOP/PAUSE/RESUME signals from `scan:control:{executionId}` and writes status updates to `scan:status:{executionId}`. Checkpoint/resume state is stored under `scan:state:{executionId}` with a 24-hour TTL.

The connection URL is provided via the `REDIS_URL` environment variable. Both templates degrade gracefully if Redis is unavailable — stop/pause signals are simply not processed.

## 5. External Integrations

| Service | Purpose | Method |
|---------|---------|--------|
| `data-ingestion` | Receive batched scanned objects and write to ClickHouse | HTTP POST (async, 500 KB batches) |
| `app-update-execution` | Report scan progress and final status | HTTP POST |
| OTLP Collector | Receive traces, metrics, and logs | HTTP OTLP protobuf |
| Core API / connector-api | Orchestrate scans; send stop/pause/resume signals via Redis | Redis Streams |

Service URLs default to Kubernetes service DNS names inside the `access-analyzer` namespace and can be overridden via environment variables (`SAVE_DATA_FUNCTION`, `APP_UPDATE_EXECUTION_FUNCTION`, `COMMON_FUNCTIONS_NAMESPACE`).

## 6. Deployment & Infrastructure

- **Build:** Multi-stage Docker builds. Python images use `uv` for reproducible dependency installation from `uv.lock`. C# images use a .NET SDK build stage publishing to an ASP.NET runtime stage.
- **Execution models:** HTTP mode for long-running servers; Job mode (`EXECUTION_MODE=job`) for Kubernetes Jobs invoked by the connector-api.
- **Non-root:** All Dockerfiles create a non-root `app` user and run all application code under that user.
- **CI/CD:** GitHub Actions — `.github/workflows/ruff.yml` lints and format-checks `template/netwrix-python` on every push/PR to `main`.
- **Registry:** Container images distributed via the Keygen OCI registry (`oci.pkg.keygen.sh`).
- **Debug mode:** Set `DEBUG_MODE=true` at image build time to include `debugpy` and expose port 5678 for remote debugging.

## 7. Security Considerations

- **Secrets:** Mounted as files at `/var/secrets/{name}` by the orchestrator. Never passed as environment variables or baked into images. `FunctionContext` rejects files outside the secrets directory (path traversal guard).
- **Non-root containers:** All Dockerfiles drop to a non-root user before the application starts.
- **Redis timeouts:** Clients use 2-second connection and socket timeouts to prevent indefinite blocking on an unresponsive Redis instance.
- **No credentials in source:** `NuGet.config` uses `%NUGET_TOKEN%` expansion; the token is supplied at build time via `--build-arg NUGET_TOKEN=...` and is not stored in the image.

## 8. Development & Testing Environment

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup steps.

- **Python:** `uv sync` installs all dependencies; `uv run pytest` runs tests; `uv run ruff check .` and `uv run ruff format .` enforce code style.
- **C#:** `dotnet restore && dotnet build` builds the framework; `dotnet test` runs unit tests in `ConnectorFramework.Tests`.
- **Code quality tools:** ruff (Python lint + format), `dotnet format` (C#).
