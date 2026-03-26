using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class StateManagerTests
{
    private static StateManager CreateManager(
        Mock<RedisSignalHandler>? redisMock = null,
        SupportedStates? states = null,
        Mock<IScanProgress>? progressMock = null)
    {
        var redis = redisMock?.Object
            ?? new RedisSignalHandler(
                Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
                NullLogger<RedisSignalHandler>.Instance);
        var progress = progressMock?.Object ?? Mock.Of<IScanProgress>();
        return new StateManager(redis, new ScanShutdownService(), progress, NullLogger<StateManager>.Instance, states);
    }

    // ── Initialization ─────────────────────────────────────────────────────

    [Fact]
    public void NewManager_StartsInRunningState()
    {
        var mgr = CreateManager();
        Assert.Equal(ScanStatus.Running, mgr.CurrentState);
    }

    [Fact]
    public void NewManager_DefaultSupportedStates_StopOnly()
    {
        var mgr = CreateManager();
        Assert.True(mgr.SupportedStates.Stop);
        Assert.False(mgr.SupportedStates.Pause);
        Assert.False(mgr.SupportedStates.Resume);
    }

    [Fact]
    public void NewManager_IsShutdown_IsFalse()
    {
        var mgr = CreateManager();
        Assert.False(mgr.IsShutdown);
    }

    // ── State transitions ──────────────────────────────────────────────────

    [Fact]
    public async Task SetState_ValidTransition_Running_To_Stopping_Succeeds()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync(ScanStatus.Stopping);
        Assert.True(result);
        Assert.Equal(ScanStatus.Stopping, mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_ValidTransition_Stopping_To_Stopped_Succeeds()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Stopping);
        var result = await mgr.SetStateAsync(ScanStatus.Stopped);
        Assert.True(result);
        Assert.Equal(ScanStatus.Stopped, mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_InvalidTransition_Returns_False_And_StateUnchanged()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Stopping);
        await mgr.SetStateAsync(ScanStatus.Stopped);

        var result = await mgr.SetStateAsync(ScanStatus.Running); // invalid from stopped
        Assert.False(result);
        Assert.Equal(ScanStatus.Stopped, mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_SameState_Returns_True()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync(ScanStatus.Running);
        Assert.True(result);
    }

    [Fact]
    public async Task SetState_ValidTransition_Running_To_Completed()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync(ScanStatus.Completed);
        Assert.True(result);
        Assert.Equal(ScanStatus.Completed, mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_ValidTransition_Running_To_Failed()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync(ScanStatus.Failed);
        Assert.True(result);
        Assert.Equal(ScanStatus.Failed, mgr.CurrentState);
    }

    // ── Pause / Resume transitions ─────────────────────────────────────────

    [Fact]
    public async Task PauseResumeSequence_AllTransitions_Succeed()
    {
        var mgr = CreateManager(states: new SupportedStates(Stop: true, Pause: true, Resume: true));

        Assert.True(await mgr.SetStateAsync(ScanStatus.Pausing));
        Assert.Equal(ScanStatus.Pausing, mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync(ScanStatus.Paused));
        Assert.Equal(ScanStatus.Paused, mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync(ScanStatus.Resuming));
        Assert.Equal(ScanStatus.Resuming, mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync(ScanStatus.Running));
        Assert.Equal(ScanStatus.Running, mgr.CurrentState);
    }

    [Fact]
    public async Task PausedToStopped_IsValid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Pausing);
        await mgr.SetStateAsync(ScanStatus.Paused);
        var result = await mgr.SetStateAsync(ScanStatus.Stopped);
        Assert.True(result);
        Assert.Equal(ScanStatus.Stopped, mgr.CurrentState);
    }

    [Fact]
    public async Task PausedToRunning_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Pausing);
        await mgr.SetStateAsync(ScanStatus.Paused);
        var result = await mgr.SetStateAsync(ScanStatus.Running); // must go through resuming
        Assert.False(result);
        Assert.Equal(ScanStatus.Paused, mgr.CurrentState);
    }

    [Fact]
    public async Task PausingToStopped_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Pausing);
        var result = await mgr.SetStateAsync(ScanStatus.Stopped);
        Assert.False(result);
        Assert.Equal(ScanStatus.Pausing, mgr.CurrentState);
    }

    [Fact]
    public async Task ResumingToPaused_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync(ScanStatus.Pausing);
        await mgr.SetStateAsync(ScanStatus.Paused);
        await mgr.SetStateAsync(ScanStatus.Resuming);
        var result = await mgr.SetStateAsync(ScanStatus.Paused);
        Assert.False(result);
        Assert.Equal(ScanStatus.Resuming, mgr.CurrentState);
    }

    // ── Callbacks ──────────────────────────────────────────────────────────

    [Fact]
    public async Task OnStateChange_Callback_ReceivesCorrectOldAndNewState()
    {
        var mgr = CreateManager();
        string? capturedOld = null;
        string? capturedNew = null;

        mgr.OnStateChange((old, @new) =>
        {
            capturedOld = old;
            capturedNew = @new;
            return Task.CompletedTask;
        });

        await mgr.SetStateAsync(ScanStatus.Stopping);

        Assert.Equal(ScanStatus.Running, capturedOld);
        Assert.Equal(ScanStatus.Stopping, capturedNew);
    }

    [Fact]
    public async Task OnStateChange_MultipleCallbacks_AllInvoked()
    {
        var mgr = CreateManager();
        var invocations = 0;

        mgr.OnStateChange((_, _) => { invocations++; return Task.CompletedTask; });
        mgr.OnStateChange((_, _) => { invocations++; return Task.CompletedTask; });

        await mgr.SetStateAsync(ScanStatus.Stopping);

        Assert.Equal(2, invocations);
    }

    [Fact]
    public async Task OnStateChange_CallbackThrows_DoesNotBlockOtherCallbacks()
    {
        var mgr = CreateManager();
        var secondInvoked = false;

        mgr.OnStateChange((_, _) => throw new Exception("callback error"));
        mgr.OnStateChange((_, _) => { secondInvoked = true; return Task.CompletedTask; });

        await mgr.SetStateAsync(ScanStatus.Stopping); // should not throw

        Assert.True(secondInvoked);
    }

    [Fact]
    public async Task MultipleTransitions_EachCallback_ReceivesCorrectStates()
    {
        var mgr = CreateManager();
        var transitions = new List<(string Old, string New)>();

        mgr.OnStateChange((old, @new) =>
        {
            transitions.Add((old, @new));
            return Task.CompletedTask;
        });

        await mgr.SetStateAsync(ScanStatus.Stopping);
        await mgr.SetStateAsync(ScanStatus.Stopped);

        Assert.Equal((ScanStatus.Running, ScanStatus.Stopping), transitions[0]);
        Assert.Equal((ScanStatus.Stopping, ScanStatus.Stopped), transitions[1]);
    }

    // ── Shutdown ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Shutdown_Completed_From_Running_Succeeds()
    {
        var redisMock = new Mock<RedisSignalHandler>(
            Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
            NullLogger<RedisSignalHandler>.Instance);
        redisMock.Setup(r => r.UpdateStatusAsync(It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        redisMock.Setup(r => r.CleanupStreamsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), Mock.Of<IScanProgress>(), NullLogger<StateManager>.Instance);
        var result = await mgr.ShutdownAsync("exec-123", ScanStatus.Completed);

        Assert.True(result);
        Assert.Equal(ScanStatus.Completed, mgr.CurrentState);
        Assert.True(mgr.IsShutdown);
    }

    [Fact]
    public async Task Shutdown_InvalidTransition_ReturnsFalse()
    {
        var redisMock = new Mock<RedisSignalHandler>(
            Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
            NullLogger<RedisSignalHandler>.Instance);

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), Mock.Of<IScanProgress>(), NullLogger<StateManager>.Instance);
        await mgr.SetStateAsync(ScanStatus.Stopping);
        await mgr.SetStateAsync(ScanStatus.Stopped);

        // stopped -> completed is invalid
        var result = await mgr.ShutdownAsync("exec-123", ScanStatus.Completed);

        Assert.False(result);
    }

    [Fact]
    public async Task Shutdown_CancelsToken()
    {
        var redisMock = new Mock<RedisSignalHandler>(
            Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
            NullLogger<RedisSignalHandler>.Instance);
        redisMock.Setup(r => r.UpdateStatusAsync(It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        redisMock.Setup(r => r.CleanupStreamsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), Mock.Of<IScanProgress>(), NullLogger<StateManager>.Instance);
        Assert.False(mgr.Token.IsCancellationRequested);

        await mgr.ShutdownAsync("exec-123", ScanStatus.Completed);

        Assert.True(mgr.Token.IsCancellationRequested);
    }

    [Fact]
    public async Task Shutdown_Failed_CallsUpdateExecutionAsync_WithFailedStatus()
    {
        var progressMock = new Mock<IScanProgress>();
        var mgr = CreateManager(progressMock: progressMock);

        await mgr.ShutdownAsync("exec-123", ScanStatus.Failed);

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Failed, null, null, It.IsAny<DateTimeOffset?>(), 0, default), Times.Once);
    }

    [Fact]
    public async Task Shutdown_Completed_CallsUpdateExecutionAsync_WithNonNullCompletedAt()
    {
        var progressMock = new Mock<IScanProgress>();
        var mgr = CreateManager(progressMock: progressMock);

        await mgr.ShutdownAsync("exec-123", ScanStatus.Completed);

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Completed, null, null, It.IsNotNull<DateTimeOffset?>(), 0, default), Times.Once);
    }

    [Fact]
    public async Task Shutdown_Paused_CallsUpdateExecutionAsync_WithNullCompletedAt()
    {
        var progressMock = new Mock<IScanProgress>();
        var mgr = CreateManager(progressMock: progressMock);
        await mgr.SetStateAsync(ScanStatus.Pausing);

        await mgr.ShutdownAsync("exec-123", ScanStatus.Paused);

        progressMock.Verify(p => p.UpdateExecutionAsync(
            ScanStatus.Paused, null, null, null, 0, default), Times.Once);
    }

    // ── Dispose ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Dispose_DoesNotThrow()
    {
        var mgr = CreateManager();
        await mgr.DisposeAsync();
    }
}
