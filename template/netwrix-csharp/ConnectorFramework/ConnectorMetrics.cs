using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Custom OTEL metric instruments for connector execution telemetry.
/// All instruments share a single Meter so they are exported together with
/// the execution's resource attributes (scan_execution_id, scan_id, source_id, etc.)
/// that are added to the OTEL resource builder at startup.
/// </summary>
internal static class ConnectorMetrics
{
    public const string MeterName = "Netwrix.ConnectorFramework";

    private static readonly Meter Meter = new(MeterName, "1.0");

    // ── Task lifecycle ────────────────────────────────────────────────────────

    /// <summary>Number of crawl tasks started within this execution.</summary>
    public static readonly Counter<long> TasksStarted = Meter.CreateCounter<long>(
        "connector.tasks.started",
        description: "Number of crawl tasks started within a scan execution");

    /// <summary>Number of crawl tasks finalised (child tasks enqueued or leaf tasks completed).</summary>
    public static readonly Counter<long> TasksCompleted = Meter.CreateCounter<long>(
        "connector.tasks.completed",
        description: "Number of crawl tasks finalised within a scan execution");

    /// <summary>
    /// Wall-clock duration of individual crawl tasks in seconds.
    /// Measured from StartTask() to FinaliseTask() for the same task reference.
    /// </summary>
    public static readonly Histogram<double> TaskDuration = Meter.CreateHistogram<double>(
        "connector.task.duration",
        unit: "s",
        description: "Wall-clock duration of individual crawl tasks in seconds");

    // ── Source rate limiting ──────────────────────────────────────────────────

    /// <summary>
    /// HTTP 429 responses received from the source system.
    /// Internal cluster URLs (*.svc.cluster.local, localhost) are excluded.
    /// </summary>
    public static readonly Counter<long> SourceRateLimits = Meter.CreateCounter<long>(
        "connector.source.rate_limits",
        description: "HTTP 429 responses received from the source system");

    // ── Execution lifecycle ───────────────────────────────────────────────────

    /// <summary>
    /// Total wall-clock duration of the job-mode execution in seconds.
    /// Recorded once per connector process at job completion.
    /// </summary>
    public static readonly Histogram<double> ExecutionDuration = Meter.CreateHistogram<double>(
        "connector.execution.duration",
        unit: "s",
        description: "Total wall-clock duration of a scan execution job in seconds");

    // ── Batch upload ──────────────────────────────────────────────────────────

    /// <summary>
    /// Number of items in each batch successfully uploaded to data-ingestion.
    /// Tagged with <c>table</c> to allow per-table breakdown.
    /// </summary>
    public static readonly Histogram<int> BatchSize = Meter.CreateHistogram<int>(
        "connector.batch.size",
        unit: "{items}",
        description: "Number of items in each batch successfully uploaded to data-ingestion");

    /// <summary>
    /// Cumulative count of objects successfully uploaded to data-ingestion.
    /// Tagged with <c>table</c> to allow per-table breakdown.
    /// </summary>
    public static readonly Counter<long> ObjectsUploaded = Meter.CreateCounter<long>(
        "connector.objects.uploaded",
        description: "Total number of objects successfully uploaded to data-ingestion");

    // ── Process resources ─────────────────────────────────────────────────────

    static ConnectorMetrics()
    {
        var process = Process.GetCurrentProcess();

        Meter.CreateObservableGauge(
            "process.memory.usage",
            () => process.WorkingSet64,
            "By",
            "Process working set memory in bytes");

        // CPU time is monotonically increasing — use ObservableCounter so consumers
        // can derive utilisation via rate().
        Meter.CreateObservableCounter(
            "process.cpu.user.time",
            () => process.UserProcessorTime.TotalSeconds,
            "s",
            "User-mode CPU time accumulated by the process in seconds");

        Meter.CreateObservableCounter(
            "process.cpu.system.time",
            () => process.PrivilegedProcessorTime.TotalSeconds,
            "s",
            "Kernel-mode CPU time accumulated by the process in seconds");
    }
}
