using System.Text.Json.Nodes;
using Netwrix.Overlord.Sdk.Cloud;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Netwrix.Overlord.Sdk.Core.State.Models;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

/// <summary>
/// Test double for <see cref="ICrawlTaskManagementPlatformFacade"/> used in integration tests
/// that need to react to <see cref="FinaliseTask"/> calls (e.g. to inject a control signal
/// into Redis after a specific number of completions).
/// </summary>
internal sealed class FakeCrawlTaskFacade : ICrawlTaskManagementPlatformFacade
{
    private int _finaliseCount;
    private readonly Func<int, Task>? _onFinalise;

    private static readonly CrawlTaskConfiguration DefaultConfig = new()
    {
        Source = new CrawlTaskConfiguration.SourcePayload
        {
            Name = "test-source",
            Reference = Guid.NewGuid(),
            ExternalReference = "test-tenant",
            CredentialsId = Guid.Empty,
            Enabled = true,
        },
        ConnectorConfigs = [],
        FeatureFlags = [],
    };

    /// <summary>Total number of <see cref="FinaliseTask"/> calls received (all update types).</summary>
    public int FinaliseCount => Volatile.Read(ref _finaliseCount);

    /// <param name="onFinalise">
    /// Optional callback invoked after each <see cref="FinaliseTask"/> call,
    /// receiving the running total. Use to inject Redis signals at precise moments.
    /// </param>
    public FakeCrawlTaskFacade(Func<int, Task>? onFinalise = null)
    {
        _onFinalise = onFinalise;
    }

    public Task<CrawlTaskConfiguration> StartTask(Guid crawlTaskReference, DateTimeOffset startDate)
        => Task.FromResult(DefaultConfig);

    public async Task FinaliseTask(APICrawlTaskProgress taskProgress)
    {
        var count = Interlocked.Increment(ref _finaliseCount);
        if (_onFinalise is not null)
            await _onFinalise(count);
    }

    public Task EnsureRegularTaskProgressUpdate(Guid taskReference, CrawlResponse taskProgress)
        => Task.CompletedTask;

    public Task<TMessage> DecryptServiceBusMessage<TMessage>(string message)
        => throw new NotSupportedException("Not used in integration tests.");

    public Task<TData> DecryptData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => throw new NotSupportedException("Not used in integration tests.");

    public Task UploadActivityRecords(List<ActivityRecord> activityRecords)
        => Task.CompletedTask;

    public Task UploadSiTRecords(CrawlContext context, List<SitObjectImportModel> objectModels,
        List<SitMappingImportModel> mappingModels, List<SitImportActionModel> actionModels,
        bool isFinal, int chunkId = 1)
        => Task.CompletedTask;

    public Task UploadSiTSchemaRecords(CrawlContext context, string tableName,
        IReadOnlyList<JsonObject> entities, bool isFinal, int chunkId = 1)
        => Task.CompletedTask;

    public Task<TData> DecryptTenancyData<TData>(byte[] encryptedKey, byte[] encryptedPayload)
        => throw new NotSupportedException("Not used in integration tests.");
}
