using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class ConnectorStateStorageTests
{
    // ── Helpers ──────────────────────────────────────────────────────────────

    private static ConnectorRequestData MakeRequest(string? scanId = "scan-test")
        => new("POST", "/", new Dictionary<string, string>(), null,
            new ExecutionContext(ScanId: scanId, ScanExecutionId: null, SourceId: null, SourceType: null, SourceVersion: null, FunctionType: null));

    private static ConnectorStateStorage CreateStorage(IHttpClientFactory factory, string? scanId = "scan-test")
        => new(MakeRequest(scanId), factory, NullLogger<ConnectorStateStorage>.Instance);

    /// <summary>Returns a factory that replies to every request with the same body/status.</summary>
    private static (Mock<HttpMessageHandler> Handler, IHttpClientFactory Factory) CreateFactory(
        string responseBody,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            // Return a fresh HttpResponseMessage each call: using var response in the SUT disposes
            // the instance after reading, so reusing a pre-created response causes ObjectDisposedException.
            .Returns<HttpRequestMessage, CancellationToken>((_, _) =>
                Task.FromResult(new HttpResponseMessage(statusCode)
                {
                    Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
                }));

        // Return a fresh HttpClient on each call — the real IHttpClientFactory does the same,
        // and it prevents ObjectDisposedException when a second call is made after the first
        // disposes its client via 'using var'.
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(() => new HttpClient(handlerMock.Object));
        return (handlerMock, factoryMock.Object);
    }

    private static string StateResponse(Dictionary<string, string> data)
        => JsonSerializer.Serialize(new { success = true, data });

    private static string EmptyStateResponse()
        => JsonSerializer.Serialize(new { success = true, data = new Dictionary<string, string>() });

    // ── TryGetAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task TryGetAsync_ReturnsNotFound_WhenKeyAbsent()
    {
        var (_, factory) = CreateFactory(EmptyStateResponse());
        var storage = CreateStorage(factory);

        var result = await storage.TryGetAsync<string>("missing");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task TryGetAsync_ReturnsValue_WhenFound()
    {
        var stateData = new Dictionary<string, string>
        {
            ["myKey"] = "\"hello\"",
        };
        var (_, factory) = CreateFactory(StateResponse(stateData));
        var storage = CreateStorage(factory);

        var result = await storage.TryGetAsync<string>("myKey");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
        Assert.Null(result.ETag);
    }

    [Fact]
    public async Task TryGetAsync_ReturnsNotFound_WhenScanIdIsNull()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        var storage = CreateStorage(factoryMock.Object, scanId: null);

        var result = await storage.TryGetAsync<string>("anyKey");

        Assert.False(result.IsSuccess);
        factoryMock.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task TryGetAsync_ThrowsStorageException_OnHttpError()
    {
        var (_, factory) = CreateFactory("{}", HttpStatusCode.InternalServerError);
        var storage = CreateStorage(factory);

        await Assert.ThrowsAsync<StateStorageException>(() => storage.TryGetAsync<string>("myKey"));
    }

    // ── SetAsync ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task SetAsync_PostsValue()
    {
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
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(() => new HttpClient(handlerMock.Object));
        var storage = CreateStorage(factoryMock.Object);

        await storage.SetAsync("cursor", "page-5");

        Assert.NotNull(capturedBody);
        var json = Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("\"cursor\"", json);
        Assert.Contains("page-5", json);
        Assert.DoesNotContain("__etag__", json);
    }

    [Fact]
    public async Task SetAsync_IsNoOp_WhenScanIdIsNull()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        var storage = CreateStorage(factoryMock.Object, scanId: null);

        await storage.SetAsync("key", "value");

        factoryMock.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }

    // ── SetIfMatchAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task SetIfMatchAsync_WritesValueUnconditionally()
    {
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
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(() => new HttpClient(handlerMock.Object));
        var storage = CreateStorage(factoryMock.Object);

        var result = await storage.SetIfMatchAsync("bookmark", "value-new", "any-etag");

        Assert.NotNull(capturedBody);
        var json = Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("\"bookmark\"", json);
        Assert.Contains("value-new", json);
        Assert.Equal(string.Empty, result);
    }

    // ── DeleteAsync ───────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteAsync_ReturnsTrueAndIssuesDelete()
    {
        HttpMethod? deleteMethod = null;
        string? deleteUrl = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((req, _) =>
            {
                deleteMethod = req.Method;
                deleteUrl = req.RequestUri!.ToString();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });

        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(() => new HttpClient(handlerMock.Object));
        var storage = CreateStorage(factoryMock.Object);

        var deleted = await storage.DeleteAsync("target");

        Assert.True(deleted);
        Assert.Equal(HttpMethod.Delete, deleteMethod);
        Assert.NotNull(deleteUrl);
        Assert.Contains("name=target", deleteUrl);
    }

    // ── DeleteAllAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteAllAsync_IssuesDeleteForPrefixMatchingKeys()
    {
        var stateData = new Dictionary<string, string>
        {
            ["source/abc/bookmark"] = "\"v1\"",
            ["source/abc/cursor"] = "\"v2\"",
            ["other/key"] = "\"v3\"",
        };
        string? deleteUrl = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        var callIndex = 0;
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((req, _) =>
            {
                if (callIndex++ == 0)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(StateResponse(stateData), Encoding.UTF8, "application/json"),
                    });
                }
                deleteUrl = req.RequestUri!.ToString();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });

        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(() => new HttpClient(handlerMock.Object));
        var storage = CreateStorage(factoryMock.Object);

        await storage.DeleteAllAsync("source/abc");

        Assert.NotNull(deleteUrl);
        Assert.True(deleteUrl!.Contains("bookmark") && deleteUrl.Contains("cursor"),
            $"Expected both bookmark and cursor in DELETE url: {deleteUrl}");
        Assert.DoesNotContain("other%2Fkey", deleteUrl);
        Assert.DoesNotContain("other/key", deleteUrl);
    }

    // ── ListAllKeysAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task ListAllKeysAsync_ReturnsKeys_MatchingPrefix()
    {
        var stateData = new Dictionary<string, string>
        {
            ["a/x"] = "\"1\"",
            ["a/y"] = "\"2\"",
            ["b/z"] = "\"3\"",
        };
        var (_, factory) = CreateFactory(StateResponse(stateData));
        var storage = CreateStorage(factory);

        var keys = new List<string>();
        await foreach (var k in storage.ListAllKeysAsync("a"))
        {
            keys.Add(k);
        }

        Assert.Equal(new[] { "a/x", "a/y" }, keys.ToArray());
    }

    [Fact]
    public async Task ListAllKeysAsync_ReturnsEmpty_WhenScanIdIsNull()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        var storage = CreateStorage(factoryMock.Object, scanId: null);

        var keys = new List<string>();
        await foreach (var k in storage.ListAllKeysAsync())
        {
            keys.Add(k);
        }

        Assert.Empty(keys);
        factoryMock.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }

    // ── ListKeysAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_ReturnsKeysAtCorrectDepth()
    {
        var stateData = new Dictionary<string, string>
        {
            ["src/tenant/site/bookmark"] = "\"v\"",
            ["src/tenant/site/cursor"] = "\"v\"",
            ["src/tenant/other/bookmark"] = "\"v\"",
            ["src/tenant/bookmark"] = "\"v\"", // depth=1 from src/tenant
        };
        var (_, factory) = CreateFactory(StateResponse(stateData));
        var storage = CreateStorage(factory);

        var depth1 = new List<string>();
        await foreach (var k in storage.ListKeysAsync("src/tenant", depth: 1))
        {
            depth1.Add(k);
        }

        var depth2 = new List<string>();
        await foreach (var k in storage.ListKeysAsync("src/tenant", depth: 2))
        {
            depth2.Add(k);
        }

        Assert.Equal(new[] { "src/tenant/bookmark" }, depth1.ToArray());
        Assert.Equal(new[] { "src/tenant/other/bookmark", "src/tenant/site/bookmark", "src/tenant/site/cursor" }, depth2.ToArray());
    }
}
