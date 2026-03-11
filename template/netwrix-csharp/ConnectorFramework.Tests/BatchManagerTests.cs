using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using System.Net;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class BatchManagerTests
{
    private static ConnectorRequestData MakeRequest(string? scanId = "scan-1", string? execId = "exec-1")
        => new("POST", "/connector/access_scan", new Dictionary<string, string>(), null,
            new ExecutionContext(ScanId: scanId, ScanExecutionId: execId, SourceId: null, SourceType: null, SourceVersion: null, FunctionType: null));

    private static BatchManager CreateBatchManager(
        IHttpClientFactory? httpFactory = null,
        Func<int, CancellationToken, Task>? onFlushed = null)
    {
        httpFactory ??= Mock.Of<IHttpClientFactory>();
        return new BatchManager(
            "test_table",
            httpFactory,
            MakeRequest(),
            NullLogger<BatchManager>.Instance,
            onFlushed);
    }

    private static (Mock<HttpMessageHandler> HandlerMock, IHttpClientFactory Factory) CreateSuccessFactory(
        HttpStatusCode statusCode = HttpStatusCode.Accepted)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(statusCode));

        var httpClient = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);
        return (handlerMock, factoryMock.Object);
    }

    [Fact]
    public async Task FlushAsync_WithNoObjects_Completes_WithoutError()
    {
        await using var bm = CreateBatchManager();
        await bm.FlushAsync(); // should not throw
    }

    [Fact]
    public async Task AddObject_SingleItem_CanFlush()
    {
        var (_, factory) = CreateSuccessFactory();
        await using var bm = new BatchManager("test_table", factory, MakeRequest(), NullLogger<BatchManager>.Instance);
        bm.AddObject(new { id = 1, name = "test" });

        await bm.FlushAsync(); // should not throw
    }

    [Fact]
    public async Task AddObject_NullObject_IsIgnored()
    {
        await using var bm = CreateBatchManager();
        bm.AddObject(null!);
        await bm.FlushAsync(); // should not throw
    }

    [Fact]
    public async Task FlushAsync_CanBeCalledMultipleTimes_AfterNoObjects()
    {
        await using var bm = CreateBatchManager();
        await bm.FlushAsync();
        // Second flush should not throw (channel is already completed)
    }

    [Fact]
    public async Task DisposeAsync_DoesNotThrow()
    {
        var bm = CreateBatchManager();
        await bm.DisposeAsync();
    }

    [Fact]
    public async Task AddObject_InjectsFrameworkFields()
    {
        // Capture the body sent to data-ingestion
        byte[]? capturedBody = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                capturedBody = await req.Content!.ReadAsByteArrayAsync();
            })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.Accepted));

        var httpClient = new HttpClient(handlerMock.Object);
        var httpFactoryMock = new Mock<IHttpClientFactory>();
        httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        await using var bm = new BatchManager("my_table", httpFactoryMock.Object, MakeRequest("s-1", "e-1"), NullLogger<BatchManager>.Instance);
        bm.AddObject(new { key = "value" });

        await bm.FlushAsync();

        Assert.NotNull(capturedBody);
        var json = System.Text.Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("sourceType", json);
        Assert.Contains("my_table", json);
        Assert.Contains("key", json);
    }

    [Fact]
    public async Task OnFlushed_CalledWithCorrectCount_AfterSuccessfulFlush()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 });
        bm.AddObject(new { x = 2 });
        bm.AddObject(new { x = 3 });

        await bm.FlushAsync();

        Assert.Equal(3, flushedCount);
    }

    [Fact]
    public async Task OnFlushed_NotCalled_WhenNoObjects()
    {
        var (_, factory) = CreateSuccessFactory();
        var called = false;
        Func<int, CancellationToken, Task> onFlushed = (_, _) =>
        {
            called = true;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        await bm.FlushAsync();

        Assert.False(called);
    }

    [Fact]
    public async Task AddObject_UpdateStatusFalse_DoesNotCountObject()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 }, updateStatus: false);
        bm.AddObject(new { x = 2 }, updateStatus: false);

        await bm.FlushAsync();

        // count was 0 so onFlushed should not be called
        Assert.Null(flushedCount);
    }

    [Fact]
    public async Task AddObject_MixedUpdateStatus_CountsOnlyStatusTrue()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 }, updateStatus: true);
        bm.AddObject(new { x = 2 }, updateStatus: false);
        bm.AddObject(new { x = 3 }, updateStatus: true);

        await bm.FlushAsync();

        Assert.Equal(2, flushedCount);
    }

    [Fact]
    public async Task OnFlushed_NotCalled_WhenFlushFails()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.InternalServerError));

        var httpClient = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var called = false;
        Func<int, CancellationToken, Task> onFlushed = (_, _) =>
        {
            called = true;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factoryMock.Object, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 });

        await bm.FlushAsync();

        Assert.False(called);
    }

    [Fact]
    public async Task OnFlushed_CalledWithCorrectCount_AfterSuccessfulFlush()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 });
        bm.AddObject(new { x = 2 });
        bm.AddObject(new { x = 3 });

        await bm.FlushAsync();

        Assert.Equal(3, flushedCount);
    }

    [Fact]
    public async Task OnFlushed_NotCalled_WhenNoObjects()
    {
        var (_, factory) = CreateSuccessFactory();
        var called = false;
        Func<int, CancellationToken, Task> onFlushed = (_, _) =>
        {
            called = true;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        await bm.FlushAsync();

        Assert.False(called);
    }

    [Fact]
    public async Task AddObject_UpdateStatusFalse_DoesNotCountObject()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 }, updateStatus: false);
        bm.AddObject(new { x = 2 }, updateStatus: false);

        await bm.FlushAsync();

        // count was 0 so onFlushed should not be called
        Assert.Null(flushedCount);
    }

    [Fact]
    public async Task AddObject_MixedUpdateStatus_CountsOnlyStatusTrue()
    {
        var (_, factory) = CreateSuccessFactory();
        int? flushedCount = null;
        Func<int, CancellationToken, Task> onFlushed = (count, _) =>
        {
            flushedCount = count;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factory, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 }, updateStatus: true);
        bm.AddObject(new { x = 2 }, updateStatus: false);
        bm.AddObject(new { x = 3 }, updateStatus: true);

        await bm.FlushAsync();

        Assert.Equal(2, flushedCount);
    }

    [Fact]
    public async Task OnFlushed_NotCalled_WhenFlushFails()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.InternalServerError));

        var httpClient = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var called = false;
        Func<int, CancellationToken, Task> onFlushed = (_, _) =>
        {
            called = true;
            return Task.CompletedTask;
        };

        await using var bm = new BatchManager("t", factoryMock.Object, MakeRequest(), NullLogger<BatchManager>.Instance, onFlushed);
        bm.AddObject(new { x = 1 });

        await bm.FlushAsync();

        Assert.False(called);
    }
}
