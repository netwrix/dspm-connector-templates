using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class RedisSignalHandlerTests
{
    private static (RedisSignalHandler Handler, Mock<IDatabase> DbMock) CreateHandler()
    {
        var dbMock = new Mock<IDatabase>();
        var multiplexerMock = new Mock<IConnectionMultiplexer>();
        multiplexerMock.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>()))
            .Returns(dbMock.Object);
        var handler = new RedisSignalHandler(multiplexerMock.Object, NullLogger<RedisSignalHandler>.Instance);
        return (handler, dbMock);
    }

    // ── CheckControlSignalAsync ────────────────────────────────────────────

    [Fact]
    public async Task CheckControlSignal_Stop_ReturnsStopAction()
    {
        var (handler, db) = CreateHandler();

        var entries = new StreamEntry[]
        {
            new StreamEntry("1234567890-0", new NameValueEntry[] { new("action", "STOP") }),
        };
        db.Setup(d => d.StreamReadAsync("scan:control:exec-1", "0", 1, CommandFlags.None))
            .ReturnsAsync(entries);

        var result = await handler.CheckControlSignalAsync("exec-1", "0");

        Assert.NotNull(result);
        Assert.Equal("STOP", result!.Value.Action);
        Assert.Equal("1234567890-0", result.Value.MessageId);
    }

    [Fact]
    public async Task CheckControlSignal_Pause_ReturnsPauseAction()
    {
        var (handler, db) = CreateHandler();
        var entries = new StreamEntry[]
        {
            new StreamEntry("1234567890-1", new NameValueEntry[] { new("action", "PAUSE") }),
        };
        db.Setup(d => d.StreamReadAsync("scan:control:exec-1", "0", 1, CommandFlags.None))
            .ReturnsAsync(entries);

        var result = await handler.CheckControlSignalAsync("exec-1", "0");

        Assert.NotNull(result);
        Assert.Equal("PAUSE", result!.Value.Action);
    }

    [Fact]
    public async Task CheckControlSignal_Resume_ReturnsResumeAction()
    {
        var (handler, db) = CreateHandler();
        var entries = new StreamEntry[]
        {
            new StreamEntry("1234567890-2", new NameValueEntry[] { new("action", "RESUME") }),
        };
        db.Setup(d => d.StreamReadAsync("scan:control:exec-1", "0", 1, CommandFlags.None))
            .ReturnsAsync(entries);

        var result = await handler.CheckControlSignalAsync("exec-1", "0");

        Assert.NotNull(result);
        Assert.Equal("RESUME", result!.Value.Action);
    }

    [Fact]
    public async Task CheckControlSignal_NoMessages_ReturnsNull()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StreamReadAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<int>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(Array.Empty<StreamEntry>());

        var result = await handler.CheckControlSignalAsync("exec-1");

        Assert.Null(result);
    }

    [Fact]
    public async Task CheckControlSignal_RedisException_ReturnsNull()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StreamReadAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<int>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisException("connection refused"));

        var result = await handler.CheckControlSignalAsync("exec-1");

        Assert.Null(result);
    }

    // ── UpdateStatusAsync ─────────────────────────────────────────────────

    [Fact]
    public async Task UpdateStatus_AddsStreamEntry_WithExpectedFields()
    {
        var (handler, db) = CreateHandler();
        // StackExchange.Redis 2.8 overload: (key, pairs, messageId?, long? maxLen, bool approx, long? minId, StreamTrimMode, flags)
        db.Setup(d => d.StreamAddAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<NameValueEntry[]>(),
                It.IsAny<RedisValue?>(),
                It.IsAny<long?>(),
                It.IsAny<bool>(),
                It.IsAny<long?>(),
                It.IsAny<StreamTrimMode>(),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync(new RedisValue("1234-0"));
        db.Setup(d => d.KeyExpireAsync(
                It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(), It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        await handler.UpdateStatusAsync("exec-1", "stopping", "Stop signal received");

        db.Verify(d => d.StreamAddAsync(
            It.Is<RedisKey>(k => k.ToString() == "scan:status:exec-1"),
            It.IsAny<NameValueEntry[]>(),
            It.IsAny<RedisValue?>(),
            It.IsAny<long?>(),
            It.IsAny<bool>(),
            It.IsAny<long?>(),
            It.IsAny<StreamTrimMode>(),
            It.IsAny<CommandFlags>()), Times.Once);
    }

    [Fact]
    public async Task UpdateStatus_RedisException_DoesNotThrow()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StreamAddAsync(It.IsAny<RedisKey>(), It.IsAny<NameValueEntry[]>(),
                It.IsAny<RedisValue?>(), It.IsAny<int?>(), It.IsAny<bool>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisException("timeout"));

        await handler.UpdateStatusAsync("exec-1", "stopping"); // should not throw
    }

    // ── CleanupStreamsAsync ────────────────────────────────────────────────

    [Fact]
    public async Task CleanupStreams_DeletesBothControlAndStatusKeys()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey[]>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(2);

        await handler.CleanupStreamsAsync("exec-1");

        db.Verify(d => d.KeyDeleteAsync(
            It.Is<RedisKey[]>(keys =>
                keys.Any(k => k.ToString() == "scan:control:exec-1") &&
                keys.Any(k => k.ToString() == "scan:status:exec-1")),
            It.IsAny<CommandFlags>()), Times.Once);
    }

    // ── Checkpoint API ────────────────────────────────────────────────────

    [Fact]
    public async Task GetState_ReturnsDeserializedValue()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StringGetAsync("scan:state:exec-1", CommandFlags.None))
            .ReturnsAsync(new RedisValue("{\"count\":42}"));

        var result = await handler.GetStateAsync<Dictionary<string, int>>("exec-1");

        Assert.NotNull(result);
        Assert.Equal(42, result!["count"]);
    }

    [Fact]
    public async Task GetState_WhenKeyMissing_ReturnsDefault()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StringGetAsync("scan:state:exec-1", CommandFlags.None))
            .ReturnsAsync(RedisValue.Null);

        var result = await handler.GetStateAsync<Dictionary<string, int>>("exec-1");

        Assert.Null(result);
    }

    [Fact]
    public async Task SetState_SerializesAndStoresValue()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<bool>(),
                It.IsAny<When>(),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        await handler.SetStateAsync("exec-1", new { lastPage = 5 });

        db.Verify(d => d.StringSetAsync(
            It.Is<RedisKey>(k => k.ToString() == "scan:state:exec-1"),
            It.IsAny<RedisValue>(),
            It.Is<TimeSpan?>(t => t == TimeSpan.FromSeconds(86400)),
            It.IsAny<bool>(),
            It.IsAny<When>(),
            It.IsAny<CommandFlags>()), Times.Once);
    }

    [Fact]
    public async Task DeleteState_RemovesKey()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        await handler.DeleteStateAsync("exec-1");

        db.Verify(d => d.KeyDeleteAsync(
            It.Is<RedisKey>(k => k.ToString() == "scan:state:exec-1"),
            It.IsAny<CommandFlags>()), Times.Once);
    }

    // ── IsHealthy ─────────────────────────────────────────────────────────

    [Fact]
    public void IsHealthy_WhenPingSucceeds_ReturnsTrue()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.Ping(CommandFlags.None)).Returns(TimeSpan.FromMilliseconds(1));

        Assert.True(handler.IsHealthy());
    }

    [Fact]
    public void IsHealthy_WhenPingThrows_ReturnsFalse()
    {
        var (handler, db) = CreateHandler();
        db.Setup(d => d.Ping(CommandFlags.None)).Throws(new RedisException("connection error"));

        Assert.False(handler.IsHealthy());
    }
}
