using System.Diagnostics;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;
using Netwrix.Overlord.Sdk.Core.Activity.Models;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class AACrawlTaskCorePlatformFacadeTests
{
    private static Mock<IScanWriter> WriterMock()
    {
        var mock = new Mock<IScanWriter>();
        mock.Setup(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    private static Mock<IScanProgress> ProgressMock()
    {
        var mock = new Mock<IScanProgress>();
        mock.Setup(p => p.Execution).Returns(new ExecutionContext(ScanId: null, ScanExecutionId: "exec-test", SourceId: null, SourceType: null, SourceVersion: null, FunctionType: null));
        mock.Setup(p => p.StartActivity(It.IsAny<string>())).Returns((Activity?)null);
        mock.Setup(p => p.UpdateExecutionAsync(
                It.IsAny<string?>(),
                It.IsAny<int?>(),
                It.IsAny<int?>(),
                It.IsAny<DateTimeOffset?>(),
                It.IsAny<int>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    private static AACorePlatformFacade CreateCore(IScanWriter? writer = null)
        => new(NullLogger<AACorePlatformFacade>.Instance, writer ?? WriterMock().Object);

    private static AACrawlTaskCorePlatformFacade CreateFacade(
        AACorePlatformFacade? core = null,
        IScanProgress? progress = null)
        => new(
            core ?? CreateCore(),
            progress ?? ProgressMock().Object,
            NullLogger<AACrawlTaskCorePlatformFacade>.Instance);

    /// <summary>
    /// Sets _lastUpdateTimestamp to a value that makes GetElapsedTime report > 5 minutes,
    /// so EnsureRegularTaskProgressUpdate will not be throttled.
    /// </summary>
    private static void SimulateElapsedMinutes(AACrawlTaskCorePlatformFacade facade, double minutes)
    {
        var field = typeof(AACrawlTaskCorePlatformFacade)
            .GetField("_lastUpdateTimestamp", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var pastTimestamp = Stopwatch.GetTimestamp() - (long)(minutes * 60 * Stopwatch.Frequency);
        field.SetValue(facade, pastTimestamp);
    }

    // ── EnsureRegularTaskProgressUpdate ───────────────────────────────────────

    [Fact]
    public async Task EnsureRegularTaskProgressUpdate_BelowThreshold_DoesNotCallUpdateExecution()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);
        // Default _lastUpdateTimestamp is Stopwatch.GetTimestamp() — elapsed is ~0 minutes

        await facade.EnsureRegularTaskProgressUpdate(Guid.NewGuid(), new CrawlResponse { ProcessedItemCount = 10 });

        progressMock.Verify(p => p.UpdateExecutionAsync(
            It.IsAny<string?>(),
            It.IsAny<int?>(),
            It.IsAny<int?>(),
            It.IsAny<DateTimeOffset?>(),
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EnsureRegularTaskProgressUpdate_AboveThreshold_CallsUpdateExecution()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);
        SimulateElapsedMinutes(facade, 6); // > 5 minutes

        await facade.EnsureRegularTaskProgressUpdate(Guid.NewGuid(), new CrawlResponse { ProcessedItemCount = 10 });

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Running,
            null,
            null,
            null,
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EnsureRegularTaskProgressUpdate_AboveThreshold_ReportsCorrectDelta()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);
        var taskId = Guid.NewGuid();

        // First update (under threshold — establishes 5 items in the dictionary)
        await facade.EnsureRegularTaskProgressUpdate(taskId, new CrawlResponse { ProcessedItemCount = 5 });

        // Simulate time passing, then update with 15 total items (delta = 15 - 0 = 15)
        SimulateElapsedMinutes(facade, 6);
        await facade.EnsureRegularTaskProgressUpdate(taskId, new CrawlResponse { ProcessedItemCount = 15 });

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Running,
            null,
            null,
            null,
            15,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── FinalizeScan ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FinalizeScan_CallsUpdateExecutionWithStatusCompleted()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);

        await facade.FinalizeScan();

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Completed,
            null,
            null,
            null,
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task FinalizeScan_NoErrors_ReturnsCompleted()
    {
        var facade = CreateFacade();

        var result = await facade.FinalizeScan();

        Assert.Equal(ScanStatus.Completed, result);
    }

    [Fact]
    public async Task FinalizeScan_WithErrors_ReturnsCompletedWithErrors()
    {
        var facade = CreateFacade();
        var taskRef = Guid.NewGuid();
        await facade.FinaliseTask(new APICrawlTaskProgress
        {
            TenancyId = Guid.NewGuid(),
            CrawlTaskReference = taskRef,
            UpdateType = CrawlTaskUpdateType.Complete,
            CrawlTaskResults = [new ApiCrawlTaskResult { ConnectorReference = Guid.NewGuid(), ItemErrorCount = 3 }],
        });

        var result = await facade.FinalizeScan();

        Assert.Equal(ScanStatus.CompletedWithErrors, result);
    }

    [Fact]
    public async Task FinalizeScan_WithErrors_CallsUpdateExecutionWithCompletedWithErrors()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);
        var taskRef = Guid.NewGuid();
        await facade.FinaliseTask(new APICrawlTaskProgress
        {
            TenancyId = Guid.NewGuid(),
            CrawlTaskReference = taskRef,
            UpdateType = CrawlTaskUpdateType.Complete,
            CrawlTaskResults = [new ApiCrawlTaskResult { ConnectorReference = Guid.NewGuid(), ItemErrorCount = 2 }],
        });

        await facade.FinalizeScan();

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.CompletedWithErrors,
            null,
            null,
            null,
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task FinalizeScan_ReportsCorrectDelta_AfterPriorProgressUpdates()
    {
        var progressMock = ProgressMock();
        var facade = CreateFacade(progress: progressMock.Object);
        var taskId = Guid.NewGuid();

        // Record some items first (below threshold so UpdateExecution not called yet)
        await facade.EnsureRegularTaskProgressUpdate(taskId, new CrawlResponse { ProcessedItemCount = 20 });

        await facade.FinalizeScan();

        // delta = 20 - 0 (reportedItemsCount) = 20
        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Completed,
            null,
            null,
            null,
            20,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── FinalizeScan — CrawlCompletion ────────────────────────────────────────

    [Fact]
    public void Initialize_WithEmptyTenancyReference_Throws()
    {
        var facade = CreateFacade();

        var ex = Assert.Throws<ArgumentException>(() =>
            facade.Initialize(
                new CrawlTaskConfiguration.SourcePayload(),
                []));

        Assert.Contains("tenancyReference", ex.Message);
    }

    [Fact]
    public async Task FinalizeScan_WritesCrawlCompletionRowPerConnectorReference()
    {
        var writerMock = WriterMock();
        var connectorRef1 = Guid.NewGuid();
        var connectorRef2 = Guid.NewGuid();
        var core = CreateCore(writerMock.Object);
        var facade = CreateFacade(core);

        facade.Initialize(
            new CrawlTaskConfiguration.SourcePayload(),
            [
                new CrawlTaskConfiguration.ConnectorConfigPayload { ConnectorReference = connectorRef1 },
                new CrawlTaskConfiguration.ConnectorConfigPayload { ConnectorReference = connectorRef2 },
            ]);

        await facade.FinalizeScan();

        writerMock.Verify(w => w.SaveObject("crawl_completions", It.IsAny<object>(), false), Times.Exactly(2));
    }

    [Fact]
    public async Task FinalizeScan_PassesScanStartTimestamp_AsCrawlCompletionTimestamp()
    {
        var writerMock = WriterMock();
        var scanStartedAt = new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);
        var core = CreateCore(writerMock.Object);
        var facade = CreateFacade(core);
        object? savedRecord = null;
        writerMock.Setup(w => w.SaveObject(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<bool>()))
            .Callback<string, object, bool>((_, record, _) => savedRecord = record);

        facade.Initialize(
            new CrawlTaskConfiguration.SourcePayload(),
            [new CrawlTaskConfiguration.ConnectorConfigPayload { ConnectorReference = Guid.NewGuid() }]);

        await facade.FinalizeScan();

        Assert.NotNull(savedRecord);
        var fullCrawlTimestampUtc = savedRecord!.GetType().GetProperty("fullCrawlTimestampUtc")!.GetValue(savedRecord);
        Assert.Equal(scanStartedAt, fullCrawlTimestampUtc);
    }

    // ── ICorePlatformFacade delegation ────────────────────────────────────────

    [Fact]
    public async Task DecryptData_DelegatesToCore()
    {
        var writerMock = WriterMock();
        var core = CreateCore(writerMock.Object);
        var facade = CreateFacade(core);

        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { value = 42 });
        var result = await facade.DecryptData<System.Text.Json.JsonElement>(Array.Empty<byte>(), payload);

        Assert.Equal(42, result.GetProperty("value").GetInt32());
    }

    [Fact]
    public async Task UploadActivityRecords_IsNoOp_UntilTableExists()
    {
        var writerMock = WriterMock();
        var core = CreateCore(writerMock.Object);
        var facade = CreateFacade(core);

        await facade.UploadActivityRecords(new List<ActivityRecord> { new() });

        writerMock.Verify(w => w.SaveObject(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<bool>()), Times.Never);
    }

    [Fact]
    public async Task DecryptServiceBusMessage_DelegatesToCore_ThrowsNotSupported()
    {
        var facade = CreateFacade();

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            facade.DecryptServiceBusMessage<object>("msg"));
    }
}
