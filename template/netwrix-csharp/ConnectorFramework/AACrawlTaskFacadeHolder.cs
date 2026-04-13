using System.Collections.Concurrent;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Singleton that holds per-scan-run <see cref="AACrawlTaskCorePlatformFacade"/> instances
/// so that inner task scopes created by <c>CrawlRunOrchestrator</c> can resolve the same
/// pre-initialized facade rather than creating an uninitialized one.
///
/// <para>
/// Lifecycle: registered in <see cref="Register"/> by <c>Handler.RunScanAsync</c> just after
/// <c>facade.Initialize()</c> is called; unregistered in the finally block after
/// <c>ICrawlRunOrchestrator.RunAsync</c> returns.
/// </para>
/// </summary>
public sealed class AACrawlTaskFacadeHolder
{
    private readonly ConcurrentDictionary<Guid, AACrawlTaskCorePlatformFacade> _facades = new();

    public void Register(Guid crawlRunReference, AACrawlTaskCorePlatformFacade facade)
        => _facades[crawlRunReference] = facade;

    public void Unregister(Guid crawlRunReference)
        => _facades.TryRemove(crawlRunReference, out _);

    public AACrawlTaskCorePlatformFacade? TryGet(Guid crawlRunReference)
        => _facades.TryGetValue(crawlRunReference, out var f) ? f : null;
}
