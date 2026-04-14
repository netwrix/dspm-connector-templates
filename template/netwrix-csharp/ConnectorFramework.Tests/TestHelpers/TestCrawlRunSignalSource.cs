using Netwrix.Overlord.Sdk.Core.Crawling;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

internal sealed class TestCrawlRunSignalSource : ICrawlRunSignalSource
{
    private volatile int _signal = (int)CrawlRunSignal.None;

    public Task<CrawlRunSignal> CheckSignalAsync(Guid crawlRunReference, CancellationToken cancellationToken)
        => Task.FromResult((CrawlRunSignal)Interlocked.Exchange(ref _signal, (int)CrawlRunSignal.None));

    public void Send(CrawlRunSignal signal)
        => Interlocked.Exchange(ref _signal, (int)signal);
}
