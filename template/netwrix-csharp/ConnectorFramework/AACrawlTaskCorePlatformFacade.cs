using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.ConnectorFramework;

public sealed class AACrawlTaskCorePlatformFacade : ICorePlatformFacade, ICrawlTaskManagementPlatformFacade
{
    private const int MaxUpdateIntervalMinutes = 5;

    private readonly AACorePlatformFacade _core;
    private readonly IScanProgress _progress;
    private readonly ILogger<AACrawlTaskCorePlatformFacade> _logger;

    private readonly ConcurrentQueue<ApiChildCrawlTask> _crawlTaskQueue = new();
    private readonly ConcurrentDictionary<Guid, int> _processedItems = new();
    private readonly ConcurrentDictionary<Guid, int> _processedErrors = new();
    private int _reportedItemsCount;
    private long _lastUpdateTimestamp = Stopwatch.GetTimestamp();
    // CAS guard: 0 = idle, 1 = updating. Prevents two concurrent callers from both
    // passing the throttle check and issuing duplicate progress updates.
    private int _updateGuard;

    private CrawlTaskConfiguration.SourcePayload? _sourcePayload;
    private List<CrawlTaskConfiguration.ConnectorConfigPayload>? _connectorConfigs;

    public AACrawlTaskCorePlatformFacade(
        AACorePlatformFacade core,
        IScanProgress progress,
        ILogger<AACrawlTaskCorePlatformFacade> logger)
    {
        ArgumentNullException.ThrowIfNull(core);
        ArgumentNullException.ThrowIfNull(progress);
        ArgumentNullException.ThrowIfNull(logger);
        _core = core;
        _progress = progress;
        _logger = logger;
    }

    // ── ICorePlatformFacade — delegate to _core ───────────────────────────────

    public Task<TData> DecryptData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => _core.DecryptData<TData>(encryptedKey, encryptedPayload);

    public Task<TData> DecryptTenancyData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => _core.DecryptTenancyData<TData>(encryptedKey, encryptedPayload);

    public Task<TMessage> DecryptServiceBusMessage<TMessage>(string message)
        => _core.DecryptServiceBusMessage<TMessage>(message);

    public Task UploadSiTSchemaRecords(CrawlContext context, string tableName, IReadOnlyList<JsonObject> entities, bool isFinal, int chunkId = 1)
        => _core.UploadSiTSchemaRecords(context, tableName, entities, isFinal, chunkId);

    public Task UploadSiTRecords(CrawlContext context, List<SitObjectImportModel> objectModels, List<SitMappingImportModel> mappingModels, List<SitImportActionModel> actionModels, bool isFinal, int chunkId = 1)
        => _core.UploadSiTRecords(context, objectModels, mappingModels, actionModels, isFinal, chunkId);

    public Task UploadActivityRecords(List<ActivityRecord> activityRecords)
        => _core.UploadActivityRecords(activityRecords);

    // ── ICrawlTaskManagementPlatformFacade ────────────────────────────────────

    /// <summary>
    /// Exposes the queue of child crawl tasks enqueued during <see cref="FinaliseTask"/>.
    /// Drain this queue after the scan loop completes to schedule sub-tasks.
    /// </summary>
    public ConcurrentQueue<ApiChildCrawlTask> CrawlTaskQueue => _crawlTaskQueue;

    /// <summary>
    /// Stores the request payloads deserialized from the connector request body.
    /// Must be called before <see cref="StartTask"/>.
    /// </summary>
    public void Initialize(
        CrawlTaskConfiguration.SourcePayload source,
        List<CrawlTaskConfiguration.ConnectorConfigPayload> configs)
    {
        _sourcePayload = source;
        _connectorConfigs = configs;
    }

    public Task<CrawlTaskConfiguration> StartTask(Guid crawlTaskReference, DateTimeOffset startDate)
    {
        if (_sourcePayload is null || _connectorConfigs is null)
        {
            throw new InvalidOperationException("Initialize() must be called before StartTask.");
        }

        return Task.FromResult(new CrawlTaskConfiguration
        {
            TenancyReference = Guid.Empty,
            FeatureFlags = [],
            Source = _sourcePayload,
            ConnectorConfigs = _connectorConfigs
        });
    }

    public async Task EnsureRegularTaskProgressUpdate(Guid taskReference, CrawlResponse taskProgress)
    {
        _processedErrors.AddOrUpdate(
            taskReference,
            taskProgress.ConnectorResults?.Sum(x => x.ItemErrorCount) ?? 0,
            (_, _) => taskProgress.ConnectorResults?.Sum(x => x.ItemErrorCount) ?? 0);

        _processedItems.AddOrUpdate(
            taskReference,
            taskProgress.ProcessedItemCount,
            (_, _) => taskProgress.ProcessedItemCount);

        // Throttle: only call the platform at most once per MaxUpdateIntervalMinutes
        if (Stopwatch.GetElapsedTime(_lastUpdateTimestamp).TotalMinutes < MaxUpdateIntervalMinutes)
        {
            return;
        }

        // CAS guard: if another caller already claimed the update slot, skip.
        if (Interlocked.CompareExchange(ref _updateGuard, 1, 0) != 0)
        {
            return;
        }

        try
        {
            using var activity = _progress.StartActivity("update-execution-progress");
            var totalItems = _processedItems.Values.Sum();
            var delta = totalItems - _reportedItemsCount;
            await _progress.UpdateExecutionAsync(
                status: ScanStatus.Running,
                incrementCompletedObjects: delta);
            _reportedItemsCount = totalItems;
            _lastUpdateTimestamp = Stopwatch.GetTimestamp();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to perform regular task update for task {TaskReference}", taskReference);
        }
        finally
        {
            Interlocked.Exchange(ref _updateGuard, 0);
        }
    }

    public Task FinaliseTask(APICrawlTaskProgress taskProgress)
    {
        if (taskProgress.ChildTasks is null)
        {
            _logger.LogDebug(
                "FinaliseTask: no child tasks for {CrawlTaskReference} — nothing to enqueue",
                taskProgress.CrawlTaskReference);
            return Task.CompletedTask;
        }

        _processedErrors.AddOrUpdate(
            taskProgress.CrawlTaskReference,
            taskProgress.CrawlTaskResults?.Sum(x => x.ItemErrorCount) ?? 0,
            (_, _) => taskProgress.CrawlTaskResults?.Sum(x => x.ItemErrorCount) ?? 0);

        _processedItems.AddOrUpdate(
            taskProgress.CrawlTaskReference,
            taskProgress.ProcessedItemCount,
            (_, _) => taskProgress.ProcessedItemCount);

        foreach (var childTask in taskProgress.ChildTasks)
        {
            _crawlTaskQueue.Enqueue(childTask);
        }

        // Remove the finalized task's entries to prevent unbounded memory growth
        // on long-running connectors with many child tasks.
        _processedItems.TryRemove(taskProgress.CrawlTaskReference, out _);
        _processedErrors.TryRemove(taskProgress.CrawlTaskReference, out _);

        return Task.CompletedTask;
    }

    public async Task FinalizeScan()
    {
        using var activity = _progress.StartActivity("finalize-scan");
        var totalItems = _processedItems.Values.Sum();
        var delta = totalItems - _reportedItemsCount;
        try
        {
            await _progress.UpdateExecutionAsync(
                status: ScanStatus.Completed,
                incrementCompletedObjects: delta);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to finalize scan status {ScanExecutionId}",
                _progress.Execution.ScanExecutionId);
            // Rethrow so the job runner can set execution status to Failed
            // rather than silently completing with an unknown status.
            throw;
        }
    }
}
