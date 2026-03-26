using System.Diagnostics;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
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
            "running",
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
            "running",
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
            "completed",
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
            "completed",
            null,
            null,
            null,
            20,
            It.IsAny<CancellationToken>()), Times.Once);
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
    public async Task UploadActivityRecords_DelegatesToCore_DoesNotFlush()
    {
        var writerMock = WriterMock();
        var core = CreateCore(writerMock.Object);
        var facade = CreateFacade(core);

        await facade.UploadActivityRecords(new List<ActivityRecord> { new() });

        writerMock.Verify(w => w.SaveObject("activity_records", It.IsAny<ActivityRecord>(), true), Times.Once);
        writerMock.Verify(w => w.FlushTablesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DecryptServiceBusMessage_DelegatesToCore_ThrowsNotSupported()
    {
        var facade = CreateFacade();

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            facade.DecryptServiceBusMessage<object>("msg"));
    }
}
