using Netwrix.Overlord.Sdk.Core.Crawling;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// AA26 implementation of <see cref="ICrawlRunSignalSource"/>.
/// Bridges <see cref="RedisSignalHandler"/> into the Module B signal polling contract.
/// Singleton — safe because the job-mode host processes exactly one scan per process lifetime;
/// <c>_lastMessageId</c> is never shared across scans.
/// </summary>
internal sealed class AA26CrawlRunSignalSource : ICrawlRunSignalSource
{
    private readonly RedisSignalHandler _redis;
    private string _lastMessageId = "0";

    public AA26CrawlRunSignalSource(RedisSignalHandler redis) => _redis = redis;

    public async Task<CrawlRunSignal> CheckSignalAsync(
        Guid crawlRunReference, CancellationToken cancellationToken)
    {
        var result = await _redis.CheckControlSignalAsync(
            crawlRunReference.ToString(), _lastMessageId, cancellationToken);

        if (result is null)
        {
            return CrawlRunSignal.None;
        }

        _lastMessageId = result.Value.MessageId;

        return result.Value.Action switch
        {
            "PAUSE" => CrawlRunSignal.Pause,
            "STOP" => CrawlRunSignal.Stop,
            "CANCEL" => CrawlRunSignal.Cancel,
            _ => CrawlRunSignal.None,
        };
    }
}
