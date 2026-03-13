using System.Collections.Concurrent;
using System.Diagnostics;
using Netwrix.ConnectorFramework;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;

namespace Netwrix.Connector;

public class AACrawlTaskCorePlatformFacade : AACorePlatformFacade, ICrawlTaskManagementPlatformFacade
{
    private const int MaxUpdateIntervalMinutes = 5;

    private readonly ConcurrentQueue<ApiChildCrawlTask> _crawlTaskQueue = new();
    private readonly ConcurrentDictionary<Guid, int> _processedItems = new();
    private readonly ConcurrentDictionary<Guid, int> _processedErrors = new();
    private int _reportedItemsCount;
    private long _lastUpdateTimestamp = Stopwatch.GetTimestamp();

    private CrawlTaskConfiguration.SourcePayload? _sourcePayload;
    private List<CrawlTaskConfiguration.ConnectorConfigPayload>? _connectorConfigs;

    public AACrawlTaskCorePlatformFacade(
        ILogger<AACrawlTaskCorePlatformFacade> logger,
        IHttpClientFactory httpClientFactory,
        FunctionContext functionContext)
        : base(logger, httpClientFactory, functionContext)
    {
    }

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

        try
        {
            using var activity = FunctionContext.StartActivity("update-execution-progress");
            var totalItems = _processedItems.Values.Sum();
            var delta = totalItems - _reportedItemsCount;
            await FunctionContext.UpdateExecutionAsync(
                status: "running",
                incrementCompletedObjects: delta);
            _reportedItemsCount = totalItems;
            _lastUpdateTimestamp = Stopwatch.GetTimestamp();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to perform regular task update for task {TaskReference}", taskReference);
        }
    }

    public Task FinaliseTask(APICrawlTaskProgress taskProgress)
    {
        if (taskProgress.ChildTasks is null)
        {
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

        return Task.CompletedTask;
    }

    public async Task FinalizeScan()
    {
        try
        {
            using var activity = FunctionContext.StartActivity("finalize-scan");
            var totalItems = _processedItems.Values.Sum();
            var delta = totalItems - _reportedItemsCount;
            await FunctionContext.UpdateExecutionAsync(
                status: "completed",
                incrementCompletedObjects: delta);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to finalize scan status {ScanExecutionId}",
                FunctionContext.ScanExecutionId);
        }
    }
}
