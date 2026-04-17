using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Netwrix.ConnectorFramework.Tests.TestHelpers;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Crawling;
using Netwrix.Overlord.Sdk.Orchestration;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

/// <summary>
/// Integration tests for CrawlRunOrchestrator pause/resume and stop behavior.
/// Uses in-memory test doubles — no Docker, Redis, or external services required.
/// </summary>
public class CrawlRunOrchestratorPauseResumeTests
{
    private const int TotalTasks = 10; // 1 root + 9 children

    private static TestCrawlTaskProcessorFactory BuildProcessorFactory() =>
        new(callIndex =>
        {
            if (callIndex == 0)
            {
                // Root task: return 9 children for the orchestrator queue (not inline)
                return Enumerable.Range(0, TotalTasks - 1)
                    .Select(i => new CrawlItemTask
                    {
                        Reference = Guid.NewGuid(),
                        ItemType = null,
                        ItemExternalReference = $"child-item-{i}",
                        ItemName = $"Child {i}",
                        AllowImmediateProcessing = false,
                    })
                    .ToList();
            }
            // Child tasks: leaf nodes, no further children
            return Array.Empty<CrawlItemTask>();
        });

    [Fact]
    public async Task PauseAfterRootTask_ResumeCompletesAllTasks()
    {
        // Arrange
        var crawlRunRef = Guid.NewGuid();
        var processorFactory = BuildProcessorFactory();
        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var signalSource = new TestCrawlRunSignalSource();
        var request = OrchestratorTestHarness.BuildRequest(crawlRunRef);

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory, signalSource);

        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Act — Run 1: hold the root task so Pause is sent before its children are enqueued.
        // Without the hold there is a race: Crawl() returns synchronously, children are enqueued,
        // and the orchestrator may pick one up before the test thread sends Pause.
        processorFactory.HoldNextCrawl();
        var run1Task = orchestrator.RunAsync(request, cts.Token);

        // Race RunAsync against the signal wait so that a fault in RunAsync (e.g.
        // OptionsValidationException thrown before any worker starts) surfaces immediately
        // rather than silently disappearing and leaving the test to time out.
        var signalWait1 = processorFactory.WaitForCallAsync(cts.Token);
        await Task.WhenAny(run1Task, signalWait1);
        if (run1Task.IsCompleted)
        {
            await run1Task; // re-throw any fault
        }

        await signalWait1; // root task started (still held in Crawl)

        signalSource.Send(CrawlRunSignal.Pause);             // enqueue Pause before root completes
        processorFactory.UnblockCrawl();                     // release root → children enqueued, orchestrator sees Pause next

        var run1ExitReason = await run1Task;
        Assert.Equal(CrawlRunExitReason.Paused, run1ExitReason);

        var callCountAfterRun1 = processorFactory.CallCount;
        Assert.True(callCountAfterRun1 >= 1,
            $"Expected at least root task to be processed; got callCount={callCountAfterRun1}");
        Assert.True(callCountAfterRun1 < TotalTasks,
            $"Expected partial progress (pause); got callCount={callCountAfterRun1}");

        // Assert queue snapshot was persisted
        var queueKey = StateStorageKeys.RunScoped(crawlRunRef.ToString(), "queue-state");
        var savedQueue = await stateStorageFactory.Storage.TryGetAsync<JsonElement>(queueKey, cts.Token);
        Assert.True(savedQueue.IsSuccess, "Queue state should be saved after pause");

        // Act — Run 2: resume using the same request and same in-memory storage
        var run2ExitReason = await orchestrator.RunAsync(request, cts.Token);
        Assert.Equal(CrawlRunExitReason.Completed, run2ExitReason);

        // Assert — all 10 tasks processed across both runs
        Assert.Equal(TotalTasks, processorFactory.CallCount);

        // Assert — queue snapshot deleted after restore
        var queueAfterRun2 = await stateStorageFactory.Storage.TryGetAsync<JsonElement>(queueKey, cts.Token);
        Assert.False(queueAfterRun2.IsSuccess,
            "Queue state key should be deleted after successful resume");
    }

    [Fact]
    public async Task StopSignal_TerminatesRunWithoutCompletingAllTasks()
    {
        // Arrange
        var processorFactory = BuildProcessorFactory();
        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var signalSource = new TestCrawlRunSignalSource();
        var request = OrchestratorTestHarness.BuildRequest(Guid.NewGuid());

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory, signalSource);

        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Act
        var runTask = orchestrator.RunAsync(request, cts.Token);

        var signalWait = processorFactory.WaitForCallAsync(cts.Token);
        await Task.WhenAny(runTask, signalWait);
        if (runTask.IsCompleted)
        {
            await runTask; // re-throw any fault
        }

        await signalWait; // root task started

        signalSource.Send(CrawlRunSignal.Stop);

        var exitReason = await runTask;
        Assert.Equal(CrawlRunExitReason.Stopped, exitReason);

        // Assert — Stop terminated the run before all tasks completed
        Assert.True(processorFactory.CallCount < TotalTasks,
            $"Expected Stop to terminate early; got callCount={processorFactory.CallCount}");
    }
}
