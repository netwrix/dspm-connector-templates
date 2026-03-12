# Glossary

Domain terms as used in `dspm-connector-templates`.

## BatchManager

Definition: A component in both the `netwrix-csharp` and `netwrix-python` templates that buffers scanned objects in memory and flushes them asynchronously to the `data-ingestion` service when the buffer exceeds 500 KB. Each ClickHouse table gets its own `BatchManager`.

Supporting information:

* In C#, obtain one via `context.GetTable("table_name")` and call `AddObject` (synchronous, never blocks on I/O; the flush happens on a background channel worker)
* In Python, `context.save_object(table, obj)` creates a per-table `BatchManager` internally and delegates to `add_object`

## Connector

Definition: A deployed function that integrates with an external data source (e.g., CIFS/SMB, SharePoint, Active Directory). Every connector implements three operations: `test_connection`, `access_scan`, and `get_object`.

Supporting information:

* In the C# templates this is expressed as an `IConnectorHandler` implementation
* In Python templates it is a `handler.py` module with a `handle(event, context)` function

## ConnectorFramework

Definition: The C# runtime library bundled inside the `netwrix-csharp` template (`ConnectorFramework/` directory). It provides `Program.cs` (bootstrap), `FunctionContext`, `BatchManager`, `StateManager`, and `RedisSignalHandler`.

Supporting information:

* Connector authors must not modify `ConnectorFramework.csproj`
* Connector-specific packages go in `function/Function.csproj`

## FunctionContext

Definition: The per-request object injected into every connector invocation. Provides access to secrets, per-table `BatchManager` instances, checkpoint state, execution progress reporting (`UpdateExecutionAsync`), OpenTelemetry spans, and caller headers.

Supporting information:

* In C# it is `Netwrix.ConnectorFramework.FunctionContext`
* In Python it is the `Context` class in `index.py`

## Execution Mode

Definition: Controls how a connector container is invoked. **HTTP mode** (default) starts a long-running HTTP server that serves repeated requests. **Job mode** (`EXECUTION_MODE=job`) runs the handler once and exits with a success/failure exit code.

Supporting information:

* Job mode is used for Kubernetes Jobs invoked by the connector-api
* Set via the `EXECUTION_MODE` environment variable

## IConnectorHandler

Definition: The C# interface that every `netwrix-csharp` connector must implement. Has three optional/required members: `MapServices` (register DI services), `MapEndpoints` (declare HTTP routes), and `HandleJobAsync` (job-mode invocation).

Supporting information:

* The framework discovers the single non-abstract implementation via reflection at startup

## RedisSignalHandler

Definition: A class in both the Python and C# templates that connects to Redis Streams to read control signals (`STOP`, `PAUSE`, `RESUME`) from `scan:control:{executionId}` and write status updates to `scan:status:{executionId}`.

Supporting information:

* If Redis is unavailable the handler degrades gracefully and scanning continues without stop capability

## ScanExecutionId

Definition: A unique identifier for a single invocation of a connector scan. It is passed in via the `Scan-Execution-Id` HTTP header (HTTP mode) or the `SCAN_EXECUTION_ID` environment variable (job mode).

Supporting information:

* The `StateManager` and `BatchManager` use it as the key for Redis Streams and for enriching ingested data records

## StateManager

Definition: A component that manages the lifecycle states of a running scan: `running → stopping → stopped`, `running → pausing → paused → resuming → running`, and `running → completed / failed`. It polls Redis at a configurable interval (default 5 seconds) for control signals.

Supporting information:

* Exposes `ShouldStopAsync` / `ShouldPauseAsync` methods (C#) or `should_stop()` / `should_pause()` methods (Python) for connectors to check
* In C# it also exposes a `CancellationToken` that is cancelled when a STOP signal arrives

## Template

Definition: A reusable scaffold that connector repositories pull at build time. A template defines the `Dockerfile`, the runtime entrypoint (`index.py` or `Program.cs`), and framework files (`StateManager`, `BatchManager`, etc.).

Supporting information:

* Connector authors only provide their `handler.py` or `Handler.cs` and a `requirements.txt` / `Function.csproj`

## uv

Definition: The Python package manager used by the Python templates. Dependencies are declared in `pyproject.toml` and pinned in `uv.lock` for reproducible builds.

Supporting information:

* Use `uv sync` to install, `uv add <pkg>` to add a dependency, and `uv run <cmd>` to run tools within the virtual environment
