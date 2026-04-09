using Netwrix.Overlord.Sdk.Cloud.Activity;
using Netwrix.Overlord.Sdk.Cloud.State;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Models.Api;
using Netwrix.Overlord.Sdk.Cloud.TaskScheduler.Processor;

namespace Netwrix.ConnectorFramework.Tests.TestHelpers;

internal sealed class TestCrawlTaskProcessorFactory : ICrawlTaskProcessorFactory
{
    private int _callCount;
    private readonly Func<int, IReadOnlyList<CrawlItemTask>> _childrenForCall;

    // Released once per call so tests can synchronize on task start
    private readonly SemaphoreSlim _taskStartedSignal = new(0);

    public TestCrawlTaskProcessorFactory(Func<int, IReadOnlyList<CrawlItemTask>> childrenForCall)
        => _childrenForCall = childrenForCall;

    public int CallCount => _callCount;

    /// <summary>Waits until a task has been picked up by the processor factory.</summary>
    public Task WaitForCallAsync(CancellationToken ct) => _taskStartedSignal.WaitAsync(ct);

    public ICrawlTaskProcessor GetCrawlTaskProcessor(
        CrawlContext context,
        ICrawlTaskCorePlatformFacade crawlTaskCorePlatformFacade,
        IStateUploader stateUploader,
        IActivityRecordLogger activityRecordLogger,
        CrawlTaskConfiguration config,
        CrawlItemTask item)
    {
        var index = Interlocked.Increment(ref _callCount) - 1;
        _taskStartedSignal.Release();
        return new TestCrawlTaskProcessor(_childrenForCall(index));
    }
}

internal sealed class TestCrawlTaskProcessor : ICrawlTaskProcessor
{
    private readonly IReadOnlyList<CrawlItemTask> _children;

    public TestCrawlTaskProcessor(IReadOnlyList<CrawlItemTask> children)
        => _children = children;

    public Task<CrawlResponse> Crawl(CancellationToken cancellationToken)
        => Task.FromResult(new CrawlResponse
        {
            ResponseCode = CrawlTaskUpdateType.Complete,
            ChildTasks = _children.ToList(),
            ConnectorResults = [],
        });
}
