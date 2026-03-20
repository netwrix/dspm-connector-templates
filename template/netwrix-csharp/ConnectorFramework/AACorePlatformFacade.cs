using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.ConnectorFramework;

public sealed class AACorePlatformFacade : ICorePlatformFacade
{
    private const string ActivityRecordsTable = "activity_records";

    private readonly ILogger<AACorePlatformFacade> _logger;
    private readonly IScanWriter _writer;

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
        foreach (var entity in entities)
        {
            _writer.SaveObject(tableName, entity);
        }

        if (isFinal)
        {
            await _writer.FlushTablesAsync(CancellationToken.None);
        }
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
        foreach (var record in activityRecords)
        {
            _writer.SaveObject(ActivityRecordsTable, record);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Uploads SiT (State in Time) records to the core platform.
    /// </summary>
    public async Task UploadSiTRecords(
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
