using System.Text.Json.Nodes;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

internal sealed class TestInnerFacade : ICrawlTaskManagementPlatformFacade
{
    public Task<CrawlTaskConfiguration> StartTask(Guid crawlTaskReference, DateTimeOffset startDate)
        => Task.FromResult(new CrawlTaskConfiguration
        {
            Source = new CrawlTaskConfiguration.SourcePayload
            {
                Reference = Guid.NewGuid(),
                Name = "Test Source",
                ExternalReference = "test-external-ref",
            }
        });

    public Task FinaliseTask(APICrawlTaskProgress taskProgress) => Task.CompletedTask;

    public Task EnsureRegularTaskProgressUpdate(Guid taskReference, CrawlResponse taskProgress)
        => Task.CompletedTask;

    public Task UploadActivityRecords(List<ActivityRecord> activityRecords) => Task.CompletedTask;

    public Task UploadSiTRecords(CrawlContext context, List<SitObjectImportModel> objectModels,
        List<SitMappingImportModel> mappingModels, List<SitImportActionModel> actionModels,
        bool isFinal, int chunkId = 1) => Task.CompletedTask;

    public Task UploadSiTSchemaRecords(CrawlContext context, string tableName,
        IReadOnlyList<JsonObject> entities, bool isFinal, int chunkId = 1) => Task.CompletedTask;

    public Task<TMessage> DecryptServiceBusMessage<TMessage>(string message)
        => throw new NotImplementedException();

    public Task<TData> DecryptData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => throw new NotImplementedException();

    public Task<TData> DecryptTenancyData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => throw new NotImplementedException();
}
