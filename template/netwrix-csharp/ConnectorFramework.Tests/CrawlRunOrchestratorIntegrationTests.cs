using Microsoft.Extensions.DependencyInjection;
using Netwrix.ConnectorFramework.Tests.TestHelpers;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Core.Exceptions;
using Netwrix.Overlord.Sdk.Orchestration;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

/// <summary>
/// Integration tests for the CrawlRunOrchestrator path wired in by T-008.
/// Uses in-memory test doubles — no Docker, Redis, or external services required.
/// </summary>
public class CrawlRunOrchestratorIntegrationTests
{
    [Fact]
    public async Task SingleTask_CompletesSuccessfully()
    {
        var processorFactory = new TestCrawlTaskProcessorFactory();
        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var request = OrchestratorTestHarness.BuildRequest(Guid.NewGuid());

        await using var container = OrchestratorTestHarness.BuildContainer(processorFactory, stateStorageFactory);
        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var exitReason = await orchestrator.RunAsync(request, cts.Token);

        Assert.Equal(CrawlRunExitReason.Completed, exitReason);
        Assert.Equal(1, processorFactory.CallCount);
    }

    [Fact]
    public async Task TransientException_WithinBudget_RetriesAndCompletes()
    {
        // Processor throws TransientException on call 0, succeeds on call 1.
        // CrawlAttemptTracker starts at 1 on first registration, so MaxAttempts=2 gives one re-queue:
        // attempt=1 < 2 on first dispatch → re-queue; attempt=2 on second dispatch → succeeds → Completed.
        var processorFactory = new TestCrawlTaskProcessorFactory(
            exceptionForCall: callIndex => callIndex == 0
                ? new TransientException("transient", new Exception("inner"))
                : null);
        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var request = OrchestratorTestHarness.BuildRequest(Guid.NewGuid());

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory,
            configureOptions: o => o.MaxAttempts = 2);
        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var exitReason = await orchestrator.RunAsync(request, cts.Token);

        Assert.Equal(CrawlRunExitReason.Completed, exitReason);
        Assert.Equal(2, processorFactory.CallCount); // call 0 (transient → re-queued) + call 1 (success)
    }

    [Fact]
    public async Task TransientException_BudgetExhausted_ScanCompletesWithDeadLetter()
    {
        // Processor always throws. MaxAttempts=2: attempt=1 < 2 → re-queue; attempt=2 < 2 → false → dead-letter.
        // The scan still exits Completed — a dead-lettered task does not fail the run.
        var processorFactory = new TestCrawlTaskProcessorFactory(
            exceptionForCall: _ => new TransientException("transient", new Exception("inner")));
        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var crawlRunRef = Guid.NewGuid();
        var request = OrchestratorTestHarness.BuildRequest(crawlRunRef);

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory,
            configureOptions: o => o.MaxAttempts = 2);
        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var exitReason = await orchestrator.RunAsync(request, cts.Token);

        Assert.Equal(CrawlRunExitReason.Completed, exitReason);
        Assert.Equal(2, processorFactory.CallCount); // call 0 (re-queued) + call 1 (dead-lettered)

        var deadLetterPrefix = StateStorageKeys.RunScoped(crawlRunRef.ToString(), "dead-letters");
        var deadLetterKeys = new List<string>();
        await foreach (var key in stateStorageFactory.Storage.ListAllKeysAsync(deadLetterPrefix, cts.Token))
        {
            deadLetterKeys.Add(key);
        }
        Assert.Single(deadLetterKeys);
    }

    // AuthException thrown from ICrawlTaskProcessor.Crawl() is caught by
    // CrawlTaskRequestHandler.ProcessCrawlTask() before it reaches the orchestrator's
    // DispatchTaskAsync catch (AuthException) block. The ConfigCache invalidation + retry
    // path in CrawlRunOrchestrator is therefore unreachable via the processor.
    // See: platform-1secure/Tests/UnitTests/Netwrix.Overlord.Sdk.Orchestration.Test/Tests/CrawlRunOrchestratorTests.cs
    [Fact(Skip = "AuthException never escapes CrawlTaskRequestHandler.ProcessCrawlTask() — " +
                 "ConfigCache invalidation path in CrawlRunOrchestrator is unreachable via the processor")]
    public Task AuthException_NeverEscapesProcessCrawlTask_ConfigCacheRetryPathUnreachable()
        => Task.CompletedTask;
}
