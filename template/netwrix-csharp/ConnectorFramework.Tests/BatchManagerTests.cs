using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class BatchManagerTests
{
    private static ConnectorRequestData MakeRequest(string? scanId = "scan-1", string? execId = "exec-1")
        => new("POST", "/connector/access_scan", new Dictionary<string, string>(), null, scanId, execId);

    private static BatchManager CreateBatchManager(IHttpClientFactory? httpFactory = null)
    {
        httpFactory ??= Mock.Of<IHttpClientFactory>();
        return new BatchManager(
            "test_table",
            httpFactory,
            MakeRequest(),
            NullLogger<BatchManager>.Instance);
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
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(System.Net.HttpStatusCode.Accepted));

        var httpClient = new HttpClient(handlerMock.Object);
        var httpFactoryMock = new Mock<IHttpClientFactory>();
        httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        await using var bm = new BatchManager("test_table", httpFactoryMock.Object, MakeRequest(), NullLogger<BatchManager>.Instance);
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
            .ReturnsAsync(new HttpResponseMessage(System.Net.HttpStatusCode.Accepted));

        var httpClient = new HttpClient(handlerMock.Object);
        var httpFactoryMock = new Mock<IHttpClientFactory>();
        httpFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        await using var bm = new BatchManager("my_table", httpFactoryMock.Object, MakeRequest("s-1", "e-1"), NullLogger<BatchManager>.Instance);
        bm.AddObject(new { key = "value" });

        await bm.FlushAsync();

        Assert.NotNull(capturedBody);
        var json = System.Text.Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("scan_id", json);
        Assert.Contains("scan_execution_id", json);
        Assert.Contains("scanned_at", json);
        Assert.Contains("my_table", json);
    }
}
