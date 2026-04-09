using Microsoft.Extensions.Logging.Abstractions;
using Netwrix.Overlord.Sdk.Core.Crawling;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class AA26CrawlRunSignalSourceTests
{
    // ── Signal mapping ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("PAUSE",   CrawlRunSignal.Pause)]
    [InlineData("STOP",    CrawlRunSignal.Stop)]
    [InlineData("CANCEL",  CrawlRunSignal.Cancel)]
    [InlineData("UNKNOWN", CrawlRunSignal.None)]
    [InlineData("pause",   CrawlRunSignal.None)]  // case-sensitive — lowercase is not a match
    public async Task CheckSignalAsync_MapsActionString_ToExpectedSignal(
        string action, CrawlRunSignal expected)
    {
        var stub = new StubRedisSignalHandler((Action: action, MessageId: "1-0"));
        var source = new AA26CrawlRunSignalSource(stub);

        var result = await source.CheckSignalAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task CheckSignalAsync_ReturnsNone_WhenNoSignalAvailable()
    {
        var stub = new StubRedisSignalHandler(null);
        var source = new AA26CrawlRunSignalSource(stub);

        var result = await source.CheckSignalAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.Equal(CrawlRunSignal.None, result);
    }

    // ── Test double ───────────────────────────────────────────────────────────

    /// <summary>
    /// Overrides <see cref="RedisSignalHandler.CheckControlSignalAsync"/> to return a fixed value
    /// without requiring a live Redis connection.
    /// </summary>
    private sealed class StubRedisSignalHandler : RedisSignalHandler
    {
        private readonly (string Action, string MessageId)? _result;

        public StubRedisSignalHandler((string Action, string MessageId)? result)
            : base(null, NullLogger<RedisSignalHandler>.Instance)
            => _result = result;

        public override Task<(string Action, string MessageId)?> CheckControlSignalAsync(
            string executionId,
            string? lastId = null,
            CancellationToken ct = default)
            => Task.FromResult(_result);
    }
}
