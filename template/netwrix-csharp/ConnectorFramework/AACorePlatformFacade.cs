using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.ConnectorFramework;

public sealed class AACorePlatformFacade : ICorePlatformFacade, IDisposable
{
    // private const string ActivityRecordsTable = "activity_records";

    private readonly ILogger<AACorePlatformFacade> _logger;
    private readonly IScanWriter _writer;
    // Serialises concurrent UploadSiTSchemaRecords calls from multiple orchestrator workers.
    // All workers share the same facade instance (via AACrawlTaskFacadeHolder) and therefore
    // the same BatchManager per table; BatchManager.AddObject enforces a single-writer contract.
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public AACorePlatformFacade(ILogger<AACorePlatformFacade> logger, IScanWriter writer)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(writer);
        _logger = logger;
        _writer = writer;
    }

    /// <summary>
    /// Data is transmitted as plain JSON; no decryption is performed in Access Analyzer connectors.
    /// </summary>
    public Task<TData> DecryptData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
    {
        var payloadString = Encoding.UTF8.GetString(encryptedPayload);
        var payloadObject = JsonSerializer.Deserialize<TData>(payloadString);
        return Task.FromResult(payloadObject
            ?? throw new InvalidOperationException("Unable to deserialize data payload."));
    }

    public async Task UploadSiTSchemaRecords(CrawlContext context, string tableName, IReadOnlyList<JsonObject> entities, bool isFinal,
        int chunkId = 1)
    {
        await _writeLock.WaitAsync();
        try
        {
            foreach (var entity in entities)
            {
                _writer.SaveObject(tableName, entity);
            }

            if (isFinal)
            {
                // Non-closing buffer flush: pushes this worker's partial batch to ClickHouse
                // immediately without closing the BatchManager channels. Required for incremental
                // data visibility on long-running scans (hours/days/weeks).
                //
                // We deliberately do NOT call FlushTablesAsync (which closes channels) because
                // CrawlRunOrchestrator runs N concurrent workers: each passes isFinal=true when
                // its own task finishes, while other workers are still running. Closing channels
                // here would corrupt writes from workers still queued behind _writeLock.
                //
                // The single closing flush is Handler.RunScanAsync after orchestrator.RunAsync():
                //   await ctx.FlushTablesAsync(CancellationToken.None);
                _writer.FlushBuffers(CancellationToken.None);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public void Dispose()
    {
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Data is transmitted as plain JSON; no decryption is performed in Access Analyzer connectors.
    /// </summary>
    public Task<TData> DecryptTenancyData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
    {
        var payloadObject = JsonSerializer.Deserialize<TData>(Encoding.UTF8.GetString(encryptedPayload));
        return Task.FromResult(payloadObject
            ?? throw new InvalidOperationException("Unable to deserialize tenancy data payload."));
    }

    public Task<TMessage> DecryptServiceBusMessage<TMessage>(string message)
    {
        throw new NotSupportedException(
            "Service bus message decryption is not supported in Access Analyzer connectors.");
    }

    public Task UploadActivityRecords(List<ActivityRecord> activityRecords)
    {
        // TODO: re-enable once we have the activity record schema in clickhouse.
        // foreach (var record in activityRecords)
        // {
        //     _writer.SaveObject(ActivityRecordsTable, record);
        // }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Uploads SiT (State in Time) records to the core platform.
    /// </summary>
    public Task UploadSiTRecords(
        CrawlContext context,
        List<SitObjectImportModel> objectModels,
        List<SitMappingImportModel> mappingModels,
        List<SitImportActionModel> actionModels,
        bool isFinal,
        int chunkId = 1)
    {
        throw new NotSupportedException(
            "Upload of graph based State in Time Records is not supported in Access Analyzer connectors.");
    }
}
