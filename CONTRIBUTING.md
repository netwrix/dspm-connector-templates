# Contributing to dspm-connector-templates

## Table of Contents

- [I Have a Question](#i-have-a-question)
- [I Want To Contribute](#i-want-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving The Documentation](#improving-the-documentation)
- [Styleguides](#styleguides)

## I Have a Question

For questions about connector development, template behaviour, or platform integration, raise an issue in this repository or reach out in the internal `#dspm-engineering` Slack channel.

## I Want To Contribute

### Reporting Bugs

If a template produces unexpected runtime behaviour, incorrect OpenTelemetry output, or breaks the stop/pause/resume contract, please open an issue with:

- Which template is affected (`netwrix-python`, `netwrix-csharp`, etc.)
- The execution mode in use (`http` or `job`)
- Minimal reproduction steps or a failing test
- Observed vs. expected behaviour, including any relevant log output

### Suggesting Enhancements

Before implementing a template change, open an issue to discuss it. Template changes affect every connector built from that template, so breaking changes to the `FunctionContext` API, `IConnectorHandler` interface, or `handler.py` / `Handler.cs` signatures require careful consideration.

Good enhancement proposals include:

- A clear description of the problem being solved
- The proposed API change and why it cannot be addressed at the connector level
- Any impact on existing connectors

### Your First Code Contribution

#### Setup — Python templates

```bash
# Install uv (https://github.com/astral-sh/uv)
curl -LsSf https://astral.sh/uv/install.sh | sh

cd template/netwrix-python
uv sync          # install all dependencies from uv.lock
uv run pytest    # run tests
uv run ruff check .       # lint
uv run ruff format .      # format
```

The same steps apply to `template/netwrix-internal-python`.

#### Setup — C# templates

```bash
# Requires .NET 8 SDK
cd template/netwrix-csharp
dotnet restore ConnectorFramework/ConnectorFramework.csproj
dotnet build
dotnet test ConnectorFramework.Tests/ConnectorFramework.Tests.csproj
```

#### Workflow

1. Create a feature branch from `main`.
2. Make your changes.
3. Ensure all tests pass and linting is clean (CI will enforce this on PR).
4. Open a pull request against `main` with a clear description of the change and its rationale.

#### Updating Python dependencies

Dependencies are managed with `uv`. To add or update a package:

```bash
cd template/netwrix-python   # or netwrix-internal-python
uv add <package>             # adds to pyproject.toml and updates uv.lock
uv sync                      # reinstalls from the updated lockfile
```

Always commit both `pyproject.toml` and `uv.lock`.

#### Updating C# dependencies

Add packages to `function/Function.csproj` only. Do not modify `ConnectorFramework/ConnectorFramework.csproj` unless you are changing the framework itself.

### Improving The Documentation

Documentation lives in:

- `README.md` — overview, template list, quick-start
- `ARCHITECTURE.md` — structure, component descriptions, system diagram
- `CONTRIBUTING.md` — this file
- `GLOSSARY.md` — domain term definitions
- `docs/STOP_PAUSE_RESUME_GUIDE.md` — stop/pause/resume implementation guide

Keep documentation accurate when the code changes. If a template API changes, update `ARCHITECTURE.md` and `GLOSSARY.md` in the same PR.

## Styleguides

### Python

All Python code must pass `ruff check` and `ruff format` (configured in `template/netwrix-python/pyproject.toml`). CI enforces this on every push and PR to `main`.

Key rules:
- Line length: 120 characters
- Imports sorted by `isort` rules (ruff `I`)
- No f-string debugging or `print()` in template code — use the `context.log` structured logger

### C#

Follow standard .NET conventions. The `ConnectorFramework` uses `SemaphoreSlim` (not `lock`) for async-safe state mutations; maintain this pattern for any new thread-shared state.

Key conventions:
- `FunctionContext` remains `sealed` and `IAsyncDisposable`
- `BatchManager` is single-writer per table — document this contract if you extend it
- Connector-specific packages go in `function/Function.csproj`; framework packages go in `ConnectorFramework/ConnectorFramework.csproj`

### Commit messages

Use short, imperative-mood subject lines:

```
Add retry logic to BatchManager flush
Fix StateManager shutdown not cancelling token on pause
Update netwrix-python Flask to 3.1
```
