using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Netwrix.ConnectorFramework.Tests.TestHelpers;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Core.Crawling;
using Netwrix.Overlord.Sdk.Orchestration;
using StackExchange.Redis;
using System.Net.Sockets;
using System.Text.Json;
using Testcontainers.Redis;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

/// <summary>
/// Integration tests for <see cref="AA26CrawlRunSignalSource"/> against a real Redis instance.
/// Verifies that control signals written to the Redis stream correctly drive the orchestrator.
///
/// Requires Docker.
/// On Rancher Desktop (macOS): set DOCKER_HOST=unix:///~/.rd/docker.sock and
/// TESTCONTAINERS_RYUK_DISABLED=true before running.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CrawlRunOrchestratorRedisIntegrationTests : IAsyncLifetime
{
    private readonly RedisContainer _redisContainer = new RedisBuilder().Build();
    private IConnectionMultiplexer _redis = null!;

    public async Task InitializeAsync()
    {
        await _redisContainer.StartAsync();
        // On Rancher Desktop (Lima VM), port forwarding to the macOS host takes a few seconds
        // after the container's own ready check passes. Poll until the TCP port is reachable.
        await WaitForTcpPortAsync(_redisContainer.GetConnectionString());
        _redis = ConnectionMultiplexer.Connect(_redisContainer.GetConnectionString());
    }

    private static async Task WaitForTcpPortAsync(string connectionString, int timeoutSeconds = 10)
    {
        var cfg = ConfigurationOptions.Parse(connectionString);
        var ep = (System.Net.IPEndPoint)cfg.EndPoints[0];
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        while (true)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(ep.Address, ep.Port, deadline.Token);
                return;
            }
            catch (Exception) when (!deadline.IsCancellationRequested)
            {
                await Task.Delay(200, deadline.Token);
            }
        }
    }

    public async Task DisposeAsync()
    {
        _redis.Dispose();
        await _redisContainer.DisposeAsync();
    }

    [Fact]
    public async Task StopSignalInRedis_TerminatesRun()
    {
        var processorFactory = new TestCrawlTaskProcessorFactory(
            childrenForCall: callIndex => callIndex == 0
                ? Enumerable.Range(0, 5).Select(i => new CrawlItemTask
                {
                    Reference = Guid.NewGuid(),
                    ItemType = null,
                    ItemExternalReference = $"child-{i}",
                    ItemName = $"Child {i}",
                    AllowImmediateProcessing = false,
                }).ToList()
                : Array.Empty<CrawlItemTask>());

        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var crawlRunRef = Guid.NewGuid();
        var request = OrchestratorTestHarness.BuildRequest(crawlRunRef);

        var loggerFactory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning));
        var signalSource = new AA26CrawlRunSignalSource(
            new RedisSignalHandler(_redis, loggerFactory.CreateLogger<RedisSignalHandler>()));

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory, signalSource);

        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Hold root task so we can inject STOP before children are enqueued.
        processorFactory.HoldNextCrawl();
        var runTask = orchestrator.RunAsync(request, cts.Token);

        var signalWait = processorFactory.WaitForCallAsync(cts.Token);
        await Task.WhenAny(runTask, signalWait);
        if (runTask.IsCompleted) await runTask;
        await signalWait;

        // Write STOP to Redis — orchestrator reads it on the next signal check.
        await _redis.GetDatabase().StreamAddAsync(
            $"scan:control:{crawlRunRef}",
            [new NameValueEntry("action", "STOP")]);

        processorFactory.UnblockCrawl();

        var exitReason = await runTask;
        Assert.Equal(CrawlRunExitReason.Stopped, exitReason);
        Assert.True(processorFactory.CallCount < 6,
            $"Expected Stop to terminate early; got callCount={processorFactory.CallCount}");
    }

    [Fact]
    public async Task PauseSignalInRedis_PersistsQueueAndResumes()
    {
        var crawlRunRef = Guid.NewGuid();
        const int totalChildren = 9;
        var processorFactory = new TestCrawlTaskProcessorFactory(
            childrenForCall: callIndex => callIndex == 0
                ? Enumerable.Range(0, totalChildren).Select(i => new CrawlItemTask
                {
                    Reference = Guid.NewGuid(),
                    ItemType = null,
                    ItemExternalReference = $"child-{i}",
                    ItemName = $"Child {i}",
                    AllowImmediateProcessing = false,
                }).ToList()
                : Array.Empty<CrawlItemTask>());

        var stateStorageFactory = new InMemoryRunStateStorageFactory();
        var request = OrchestratorTestHarness.BuildRequest(crawlRunRef);

        var loggerFactory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning));
        var signalSource = new AA26CrawlRunSignalSource(
            new RedisSignalHandler(_redis, loggerFactory.CreateLogger<RedisSignalHandler>()));

        await using var container = OrchestratorTestHarness.BuildContainer(
            processorFactory, stateStorageFactory, signalSource);

        var orchestrator = container.GetRequiredService<ICrawlRunOrchestrator>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // ── Phase 1: Pause ────────────────────────────────────────────────────────
        // Hold root task and inject PAUSE before its children are enqueued.
        processorFactory.HoldNextCrawl();
        var run1Task = orchestrator.RunAsync(request, cts.Token);

        var signalWait1 = processorFactory.WaitForCallAsync(cts.Token);
        await Task.WhenAny(run1Task, signalWait1);
        if (run1Task.IsCompleted) await run1Task;
        await signalWait1;

        await _redis.GetDatabase().StreamAddAsync(
            $"scan:control:{crawlRunRef}",
            [new NameValueEntry("action", "PAUSE")]);

        processorFactory.UnblockCrawl();

        var run1ExitReason = await run1Task;
        Assert.Equal(CrawlRunExitReason.Paused, run1ExitReason);

        var queueKey = StateStorageKeys.RunScoped(crawlRunRef.ToString(), "queue-state");
        var snapshot = await stateStorageFactory.Storage.TryGetAsync<JsonElement>(queueKey, cts.Token);
        Assert.True(snapshot.IsSuccess, "Queue snapshot should be persisted after pause.");

        // ── Phase 2: Resume ───────────────────────────────────────────────────────
        var run2ExitReason = await orchestrator.RunAsync(request, cts.Token);
        Assert.Equal(CrawlRunExitReason.Completed, run2ExitReason);

        var queueAfterResume = await stateStorageFactory.Storage.TryGetAsync<JsonElement>(queueKey, cts.Token);
        Assert.False(queueAfterResume.IsSuccess, "Queue snapshot should be deleted after resume completes.");
        Assert.Equal(totalChildren + 1, processorFactory.CallCount);
    }
}
