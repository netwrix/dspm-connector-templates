using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class StateManagerTests
{
    private static StateManager CreateManager(
        Mock<RedisSignalHandler>? redisMock = null,
        SupportedStates? states = null)
    {
        var redis = redisMock?.Object
            ?? new RedisSignalHandler(
                Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
                NullLogger<RedisSignalHandler>.Instance);
        return new StateManager(redis, new ScanShutdownService(), NullLogger<StateManager>.Instance, states);
    }

    // ── Initialization ─────────────────────────────────────────────────────

    [Fact]
    public void NewManager_StartsInRunningState()
    {
        var mgr = CreateManager();
        Assert.Equal("running", mgr.CurrentState);
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
        var result = await mgr.SetStateAsync("stopping");
        Assert.True(result);
        Assert.Equal("stopping", mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_ValidTransition_Stopping_To_Stopped_Succeeds()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("stopping");
        var result = await mgr.SetStateAsync("stopped");
        Assert.True(result);
        Assert.Equal("stopped", mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_InvalidTransition_Returns_False_And_StateUnchanged()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("stopping");
        await mgr.SetStateAsync("stopped");

        var result = await mgr.SetStateAsync("running"); // invalid from stopped
        Assert.False(result);
        Assert.Equal("stopped", mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_SameState_Returns_True()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync("running");
        Assert.True(result);
    }

    [Fact]
    public async Task SetState_ValidTransition_Running_To_Completed()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync("completed");
        Assert.True(result);
        Assert.Equal("completed", mgr.CurrentState);
    }

    [Fact]
    public async Task SetState_ValidTransition_Running_To_Failed()
    {
        var mgr = CreateManager();
        var result = await mgr.SetStateAsync("failed");
        Assert.True(result);
        Assert.Equal("failed", mgr.CurrentState);
    }

    // ── Pause / Resume transitions ─────────────────────────────────────────

    [Fact]
    public async Task PauseResumeSequence_AllTransitions_Succeed()
    {
        var mgr = CreateManager(states: new SupportedStates(Stop: true, Pause: true, Resume: true));

        Assert.True(await mgr.SetStateAsync("pausing"));
        Assert.Equal("pausing", mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync("paused"));
        Assert.Equal("paused", mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync("resuming"));
        Assert.Equal("resuming", mgr.CurrentState);

        Assert.True(await mgr.SetStateAsync("running"));
        Assert.Equal("running", mgr.CurrentState);
    }

    [Fact]
    public async Task PausedToStopped_IsValid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("pausing");
        await mgr.SetStateAsync("paused");
        var result = await mgr.SetStateAsync("stopped");
        Assert.True(result);
        Assert.Equal("stopped", mgr.CurrentState);
    }

    [Fact]
    public async Task PausedToRunning_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("pausing");
        await mgr.SetStateAsync("paused");
        var result = await mgr.SetStateAsync("running"); // must go through resuming
        Assert.False(result);
        Assert.Equal("paused", mgr.CurrentState);
    }

    [Fact]
    public async Task PausingToStopped_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("pausing");
        var result = await mgr.SetStateAsync("stopped");
        Assert.False(result);
        Assert.Equal("pausing", mgr.CurrentState);
    }

    [Fact]
    public async Task ResumingToPaused_IsInvalid()
    {
        var mgr = CreateManager();
        await mgr.SetStateAsync("pausing");
        await mgr.SetStateAsync("paused");
        await mgr.SetStateAsync("resuming");
        var result = await mgr.SetStateAsync("paused");
        Assert.False(result);
        Assert.Equal("resuming", mgr.CurrentState);
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

        await mgr.SetStateAsync("stopping");

        Assert.Equal("running", capturedOld);
        Assert.Equal("stopping", capturedNew);
    }

    [Fact]
    public async Task OnStateChange_MultipleCallbacks_AllInvoked()
    {
        var mgr = CreateManager();
        var invocations = 0;

        mgr.OnStateChange((_, _) => { invocations++; return Task.CompletedTask; });
        mgr.OnStateChange((_, _) => { invocations++; return Task.CompletedTask; });

        await mgr.SetStateAsync("stopping");

        Assert.Equal(2, invocations);
    }

    [Fact]
    public async Task OnStateChange_CallbackThrows_DoesNotBlockOtherCallbacks()
    {
        var mgr = CreateManager();
        var secondInvoked = false;

        mgr.OnStateChange((_, _) => throw new Exception("callback error"));
        mgr.OnStateChange((_, _) => { secondInvoked = true; return Task.CompletedTask; });

        await mgr.SetStateAsync("stopping"); // should not throw

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

        await mgr.SetStateAsync("stopping");
        await mgr.SetStateAsync("stopped");

        Assert.Equal(("running", "stopping"), transitions[0]);
        Assert.Equal(("stopping", "stopped"), transitions[1]);
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

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), NullLogger<StateManager>.Instance);
        var result = await mgr.ShutdownAsync("exec-123", "completed");

        Assert.True(result);
        Assert.Equal("completed", mgr.CurrentState);
        Assert.True(mgr.IsShutdown);
    }

    [Fact]
    public async Task Shutdown_InvalidTransition_ReturnsFalse()
    {
        var redisMock = new Mock<RedisSignalHandler>(
            Mock.Of<StackExchange.Redis.IConnectionMultiplexer>(),
            NullLogger<RedisSignalHandler>.Instance);

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), NullLogger<StateManager>.Instance);
        await mgr.SetStateAsync("stopping");
        await mgr.SetStateAsync("stopped");

        // stopped -> completed is invalid
        var result = await mgr.ShutdownAsync("exec-123", "completed");

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

        var mgr = new StateManager(redisMock.Object, new ScanShutdownService(), NullLogger<StateManager>.Instance);
        Assert.False(mgr.Token.IsCancellationRequested);

        await mgr.ShutdownAsync("exec-123", "completed");

        Assert.True(mgr.Token.IsCancellationRequested);
    }

    // ── Dispose ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Dispose_DoesNotThrow()
    {
        var mgr = CreateManager();
        await mgr.DisposeAsync();
    }
}
