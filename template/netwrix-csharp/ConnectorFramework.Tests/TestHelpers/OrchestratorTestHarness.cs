using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Netwrix.Overlord.Sdk.Cloud.Activity;
using Netwrix.Overlord.Sdk.Cloud.Resilience;
using Netwrix.Overlord.Sdk.Cloud.State;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Processor;
using Netwrix.Overlord.Sdk.Cloud.Tenancy;
using Netwrix.Overlord.Sdk.Core.Caching;
using Netwrix.Overlord.Sdk.Core.Crawling;
using Netwrix.Overlord.Sdk.Core.Storage;
using Netwrix.Overlord.Sdk.Core.TaskScheduler;
using Netwrix.Overlord.Sdk.Orchestration;
using Polly;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

internal sealed class InMemoryRunStateStorageFactory : IRunStateStorageFactory
{
    public InMemoryStateStorage Storage { get; } = new();
    public IStateStorage Create(string? scanContextId) => Storage;
}

internal static class OrchestratorTestHarness
{
    /// <summary>
    /// Builds a DI container with Module B wired to in-memory test doubles.
    /// </summary>
    public static ServiceProvider BuildContainer(
        TestCrawlTaskProcessorFactory processorFactory,
        InMemoryRunStateStorageFactory stateStorageFactory,
        ICrawlRunSignalSource? signalSource = null)
    {
        var services = new ServiceCollection();
        var emptyConfig = new ConfigurationBuilder().Build();

        services.AddLogging();
        // Provide a no-op resilience provider so CrawlRunOrchestrator can resolve its "retry" pipeline.
        var mockPipelines = new Mock<IResiliencePipelineProvider<string>>();
        mockPipelines.Setup(p => p.GetPipeline(It.IsAny<string>())).Returns(ResiliencePipeline.Empty);
        services.AddSingleton(mockPipelines.Object);

        // Options — set before AddCrawlRunOrchestration so they survive the empty section bind
        services.Configure<CrawlRunOrchestratorOptions>(o =>
        {
            o.MaxWorkers = 1;
            o.MaxConcurrencyPerSource = 1;
            o.MaxAttempts = 1;
            o.MaxAuthRetryAttempts = 1;
            o.MaxHashMismatchAttempts = 1;
            o.ConfigCacheTtl = TimeSpan.FromMinutes(5);
        });

        services.AddSingleton<IRunStateStorageFactory>(stateStorageFactory);

        if (signalSource is not null)
        {
            services.AddSingleton(signalSource);
        }

        // Scoped per worker scope (CrawlTaskRequestHandler dependencies)
        services.AddScoped<ICrawlTaskProcessorFactory>(_ => processorFactory);
        services.AddScoped<IStateUploader>(_ => Mock.Of<IStateUploader>());
        services.AddScoped<IActivityRecordLogger>(_ => Mock.Of<IActivityRecordLogger>());
        services.AddScoped<ITenancyService>(_ => Mock.Of<ITenancyService>());
        services.AddScoped<IOperationCache, NullOperationCache>();

        // Register TestInnerFacade as concrete type; AddCrawlRunOrchestration<T> resolves it
        // by concrete type to build the decorator, so it must be registered before the call.
        services.AddScoped<TestInnerFacade>();

        // CrawlTaskRequestHandler is NOT registered by AddCrawlRunOrchestration;
        // the connector host registers it explicitly (see ServiceCollectionExtensions.cs).
        services.AddScoped<CrawlTaskRequestHandler>();

        // Wires: CrawlRunOrchestrationFacade decorator + all three facade interface aliases +
        // ICrawlRunOrchestrator singleton + ICrawlRunOrchestratorRegistry
        services.AddCrawlRunOrchestration<TestInnerFacade>(emptyConfig);

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Builds a minimal <see cref="CrawlRunRequest"/> for orchestration tests.
    /// Pass the same instance to both Run 1 and Run 2 to ensure the resume path
    /// uses the same <see cref="CrawlRunRequest.CrawlRunReference"/> as the pause path.
    /// </summary>
    public static CrawlRunRequest BuildRequest(Guid crawlRunReference) =>
        new()
        {
            CrawlRunReference = crawlRunReference,
            RootCrawlTaskReference = Guid.NewGuid(),
            TenancyReference = Guid.NewGuid(),
            SourceReference = Guid.NewGuid(),
            ImportBatchReference = Guid.NewGuid(),
            CrawlType = CrawlType.Full,
            ConnectorReferences = [Guid.NewGuid()],
            ItemType = null,
            ItemExternalReference = "root-item",
            ItemName = "Root",
        };
}
