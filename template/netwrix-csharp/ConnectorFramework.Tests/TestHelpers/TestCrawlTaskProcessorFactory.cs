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

    // Released once per call so tests can synchronize on task start.
    private readonly SemaphoreSlim _taskStartedSignal = new(0);

    // When set, the next created processor will await this before returning from Crawl().
    // Cleared atomically when consumed so only the intended processor is held.
    private TaskCompletionSource<bool>? _nextCrawlBlocker;

    public TestCrawlTaskProcessorFactory(Func<int, IReadOnlyList<CrawlItemTask>> childrenForCall)
        => _childrenForCall = childrenForCall;

    public int CallCount => _callCount;

    /// <summary>Waits until a task has been picked up by the processor factory.</summary>
    public Task WaitForCallAsync(CancellationToken ct) => _taskStartedSignal.WaitAsync(ct);

    /// <summary>
    /// Causes the next processor's <c>Crawl()</c> to block until <see cref="UnblockCrawl"/> is called.
    /// Use in tests to deterministically send signals before a task's children are enqueued.
    /// </summary>
    public void HoldNextCrawl()
        => _nextCrawlBlocker = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Releases the processor held by <see cref="HoldNextCrawl"/>.</summary>
    public void UnblockCrawl() => _nextCrawlBlocker?.TrySetResult(true);

    public ICrawlTaskProcessor GetCrawlTaskProcessor(
        CrawlContext context,
        ICrawlTaskCorePlatformFacade crawlTaskCorePlatformFacade,
        IStateUploader stateUploader,
        IActivityRecordLogger activityRecordLogger,
        CrawlTaskConfiguration config,
        CrawlItemTask item)
    {
        var index = Interlocked.Increment(ref _callCount) - 1;
        // Capture the blocker's Task without clearing the field — UnblockCrawl() needs
        // the TCS reference to be intact when it calls TrySetResult.
        // With MaxWorkers=1 only one processor is in-flight at a time, so all processors
        // created after UnblockCrawl() will get an already-completed Task and won't block.
        var blocker = _nextCrawlBlocker?.Task;
        _taskStartedSignal.Release();
        return new TestCrawlTaskProcessor(_childrenForCall(index), blocker);
    }
}

internal sealed class TestCrawlTaskProcessor : ICrawlTaskProcessor
{
    private readonly IReadOnlyList<CrawlItemTask> _children;
    private readonly Task? _blocker;

    public TestCrawlTaskProcessor(IReadOnlyList<CrawlItemTask> children, Task? blocker = null)
    {
        _children = children;
        _blocker = blocker;
    }

    public async Task<CrawlResponse> Crawl(CancellationToken cancellationToken)
    {
        if (_blocker is not null)
        {
            await _blocker.WaitAsync(cancellationToken);
        }

        return new CrawlResponse
        {
            ResponseCode = CrawlTaskUpdateType.Complete,
            ChildTasks = _children.ToList(),
            ConnectorResults = [],
        };
    }
}
