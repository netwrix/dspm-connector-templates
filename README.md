# dspm-connector-templates

Function templates for building DSPM connectors. Each template provides the runtime scaffolding — HTTP server, job-mode runner, OpenTelemetry instrumentation, Redis-based stop/pause/resume signals, and batched data ingestion — so connector authors only need to implement their scanning logic.

## Templates

| Template | Language | Purpose |
|----------|----------|---------|
| `netwrix-python` | Python 3.12 | External source and IAM connectors |
| `netwrix-internal-python` | Python 3.12 | Internal common platform functions |
| `netwrix-csharp` | C# / .NET 8 | External source and IAM connectors |
| `netwrix-internal-csharp` | C# / .NET 8 | Internal common platform functions |

## Prerequisites

- Docker (for building container images)
- .NET 8 SDK (for C# templates)
- Python 3.12 + [uv](https://github.com/astral-sh/uv) (for Python templates)

## Using a Template

Connector repositories reference these templates in their `stack.yml`. The templates are pulled automatically at build time.

```yaml
functions:
  my-connector:
    lang: netwrix-python
    handler: ./functions/my-connector
    image: my-connector:latest
```

### Template selection

- Use `netwrix-python` or `netwrix-csharp` for connectors that scan external data sources and ingest data into ClickHouse.
- Use `netwrix-internal-python` or `netwrix-internal-csharp` for internal platform functions that do not scan external sources.

## Template Features

### Dual Execution Modes

All templates support two execution modes controlled by the `EXECUTION_MODE` environment variable:

- **HTTP mode** (default): starts a long-running HTTP server (Flask/Waitress for Python, ASP.NET Core for C#).
- **Job mode** (`EXECUTION_MODE=job`): runs the handler once and exits. Used for Kubernetes jobs invoked by the connector-api.

### Stop / Pause / Resume

The `netwrix-python` and `netwrix-csharp` templates include a `StateManager` that monitors Redis Streams for control signals (`STOP`, `PAUSE`, `RESUME`) sent by the Core API during a running scan.

See [docs/STOP_PAUSE_RESUME_GUIDE.md](docs/STOP_PAUSE_RESUME_GUIDE.md) for full implementation guidance.

### Batched Data Ingestion

Both the `netwrix-csharp` and `netwrix-python` templates include a `BatchManager` that buffers scanned objects in memory and flushes them to the `data-ingestion` service in batches (flush threshold: 500 KB). In C#, `BatchManager` instances are created per table via `context.GetTable("table_name")`. In Python, `context.save_object(table, obj)` creates a per-table `BatchManager` internally.

### OpenTelemetry

All templates export distributed traces, metrics, and logs to an OTLP-compatible collector. Configure the endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT` (default: `http://otel-collector.access-analyzer.svc.cluster.local:4318`). Set `OTEL_ENABLED=false` to disable.

### Secrets

Secrets are loaded from files mounted at `/var/secrets/{name}` (connector-api) or `/var/openfaas/secrets/{name}` (fallback). Access them via `context.Secrets["name"]` (C#) or `context.secrets["name"]` (Python).

## Build

### Python templates

Python templates do not require a separate build step — dependencies are installed at container build time via `uv sync` in the Dockerfile.

```bash
docker build -t my-connector:latest -f template/netwrix-python/Dockerfile .
```

### C# templates

```bash
cd template/netwrix-csharp
dotnet build ConnectorFramework/ConnectorFramework.csproj
```

Or build the container image directly:

```bash
docker build -t my-connector:latest -f template/netwrix-csharp/Dockerfile .
```

## Develop

### Python templates

```bash
cd template/netwrix-python
uv sync
uv run ruff check .
uv run ruff format .
```

### C# templates

```bash
cd template/netwrix-csharp
dotnet restore ConnectorFramework/ConnectorFramework.csproj
dotnet build
```

## Test

### Python templates

```bash
cd template/netwrix-python
uv run pytest
```

The CI pipeline runs `ruff check` and `ruff format --check` on every push/PR to `main` (see `.github/workflows/ruff.yml`).

### C# templates

```bash
cd template/netwrix-csharp
dotnet test ConnectorFramework.Tests/ConnectorFramework.Tests.csproj
```

## Deploy

Connector containers are built as multi-stage Docker images and distributed via the Keygen OCI registry (`oci.pkg.keygen.sh`). Connector repositories reference these templates in their `stack.yml`, and images are built and pushed by CI/CD pipelines. Set `EXECUTION_MODE=job` for Kubernetes Job deployments or leave unset for long-running HTTP server mode.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
