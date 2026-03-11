using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Netwrix.ConnectorFramework;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.Connector;

public class AACorePlatformFacade : ICorePlatformFacade
{
    protected readonly ILogger _logger;
    protected readonly IHttpClientFactory _httpClientFactory;
    protected readonly FunctionContext FunctionContext;

    public AACorePlatformFacade(
        ILogger<AACorePlatformFacade> logger,
        IHttpClientFactory httpClientFactory,
        FunctionContext functionContext)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        FunctionContext = functionContext;
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
        // Activity upload not implemented for Access Analyzer connector.
        // TODO T2: Implement or document as intentionally unsupported with NotSupportedException.
        return Task.CompletedTask;
    }

    /// <summary>
    /// Uploads SiT (State in Time) records to the core platform.
    ///
    /// NOTE: The object-type label map (Guid to type name) is connector-specific and must be
    /// added by the connector developer in their own project — do not add it to the template.
    /// See TODO T10.
    /// </summary>
    public async Task UploadSiTRecords(
        CrawlContext context,
        List<SitObjectImportModel> objectModels,
        List<SitMappingImportModel> mappingModels,
        List<SitImportActionModel> actionModels,
        bool isFinal,
        int chunkId = 1)
    {
        using var activity = FunctionContext.StartActivity("upload-sit-records");

        foreach (var obj in objectModels)
        {
            _logger.LogInformation("Object {Type} {Count} properties",
                obj.Type, obj.Properties?.Count ?? 0);
            FunctionContext.GetTable("objects").AddObject(obj);
        }

        // TODO T1: Implement mapping model upload — FunctionContext.GetTable("mapping").AddObject(m)
        // TODO T1: Implement action model upload  — FunctionContext.GetTable("action").AddObject(a)

        if (isFinal)
        {
            _logger.LogInformation("Final upload — flushing all pending batches");
            await FunctionContext.FlushTablesAsync();
        }
    }
}
