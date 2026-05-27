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

    private static ConnectorStateClient CreateClient(HttpMessageHandler handler)
        => new(
            new HttpClient(handler) { BaseAddress = new Uri("http://connector-state/") },
            NullLogger<ConnectorStateClient>.Instance);

    /// <summary>Returns a client that replies to every request with the same body/status.</summary>
    private static ConnectorStateClient CreateClient(
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
        return CreateClient(handlerMock.Object);
    }

    private static ConnectorStateStorage CreateStorage(ConnectorStateClient client, string? scanId = "scan-test")
        => new(MakeRequest(scanId), client, NullLogger<ConnectorStateStorage>.Instance);

    /// <summary>Flat JSON dict — the format returned by GET /{scanId} and GET /{scanId}/keys/{key}.</summary>
    private static string FlatState(Dictionary<string, string> data)
        => JsonSerializer.Serialize(data);

    /// <summary>JSON array — the format returned by GET /{scanId}/keys.</summary>
    private static string KeyList(params string[] keys)
        => JsonSerializer.Serialize(keys);

    // ── TryGetAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task TryGetAsync_ReturnsNotFound_WhenKeyAbsent()
    {
        var storage = CreateStorage(CreateClient("{}", HttpStatusCode.NotFound));

        var result = await storage.TryGetAsync<string>("missing");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task TryGetAsync_ReturnsValue_WhenFound()
    {
        var stateData = new Dictionary<string, string> { ["myKey"] = "\"hello\"" };
        var storage = CreateStorage(CreateClient(FlatState(stateData)));

        var result = await storage.TryGetAsync<string>("myKey");

        Assert.True(result.IsSuccess);
        Assert.Equal("hello", result.Value);
        Assert.Null(result.ETag);
    }

    [Fact]
    public async Task TryGetAsync_ReturnsNotFound_WhenScanIdIsNull()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var storage = CreateStorage(CreateClient(handlerMock.Object), scanId: null);

        var result = await storage.TryGetAsync<string>("anyKey");

        Assert.False(result.IsSuccess);
        handlerMock.Protected().Verify(
            "SendAsync", Times.Never(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    [Fact]
    public async Task TryGetAsync_ThrowsStorageException_OnHttpError()
    {
        var storage = CreateStorage(CreateClient("{}", HttpStatusCode.InternalServerError));

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
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.SetAsync("cursor", "page-5");

        Assert.NotNull(capturedBody);
        var json = Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("\"cursor\"", json);
        Assert.Contains("page-5", json);
        Assert.DoesNotContain("scanId", json);
        Assert.DoesNotContain("__etag__", json);
    }

    [Fact]
    public async Task SetAsync_IsNoOp_WhenScanIdIsNull()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var storage = CreateStorage(CreateClient(handlerMock.Object), scanId: null);

        await storage.SetAsync("key", "value");

        handlerMock.Protected().Verify(
            "SendAsync", Times.Never(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
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
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        var result = await storage.SetIfMatchAsync("bookmark", "value-new", "any-etag");

        Assert.NotNull(capturedBody);
        var json = Encoding.UTF8.GetString(capturedBody!);
        Assert.Contains("\"bookmark\"", json);
        Assert.Contains("value-new", json);
        Assert.DoesNotContain("scanId", json);
        Assert.Equal(string.Empty, result);
    }

    // ── DeleteAsync ───────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteAsync_ReturnsTrueAndIssuesDelete()
    {
        HttpMethod? deleteMethod = null;
        string? deletePath = null;
        string? deleteBody = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                deleteMethod = req.Method;
                deletePath = req.RequestUri!.AbsolutePath;
                deleteBody = req.Content is not null ? await req.Content.ReadAsStringAsync() : null;
                return new HttpResponseMessage(HttpStatusCode.OK);
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        var deleted = await storage.DeleteAsync("target");

        Assert.True(deleted);
        Assert.Equal(HttpMethod.Delete, deleteMethod);
        Assert.Equal("/scan-test/keys", deletePath);
        Assert.NotNull(deleteBody);
        Assert.Contains("target", deleteBody);
    }

    [Fact]
    public async Task DeleteAsync_PropagatesCancellation()
    {
        // Before the OperationCanceledException fix, the catch (Exception ex) block in each HTTP
        // method would wrap cancellation as StateStorageException, hiding the cancellation signal.
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((_, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => storage.DeleteAsync("key", cts.Token));
    }

    // ── DeleteAllAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteAllAsync_IssuesSingleDeleteWithPrefixQuery()
    {
        HttpMethod? deleteMethod = null;
        string? deletePath = null;
        string? deleteQuery = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((req, _) =>
            {
                deleteMethod = req.Method;
                deletePath = req.RequestUri!.AbsolutePath;
                deleteQuery = req.RequestUri.Query;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.DeleteAllAsync("source/abc");

        Assert.Equal(HttpMethod.Delete, deleteMethod);
        Assert.Equal("/scan-test/keys", deletePath);
        Assert.Contains("prefix=source%2Fabc", deleteQuery);
    }

    [Fact]
    public async Task DeleteAllAsync_EmptyPrefix_DeletesAllState()
    {
        HttpMethod? deleteMethod = null;
        string? deletePath = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((req, _) =>
            {
                deleteMethod = req.Method;
                deletePath = req.RequestUri!.AbsolutePath;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.DeleteAllAsync("");

        Assert.Equal(HttpMethod.Delete, deleteMethod);
        Assert.Equal("/scan-test", deletePath);
    }

    // ── ListAllKeysAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task ListAllKeysAsync_ReturnsKeys_MatchingPrefix()
    {
        var storage = CreateStorage(CreateClient(KeyList("a/x", "a/y", "b/z")));

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
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var storage = CreateStorage(CreateClient(handlerMock.Object), scanId: null);

        var keys = new List<string>();
        await foreach (var k in storage.ListAllKeysAsync())
        {
            keys.Add(k);
        }

        Assert.Empty(keys);
        handlerMock.Protected().Verify(
            "SendAsync", Times.Never(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    // ── ListKeysAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_ReturnsKeysAtCorrectDepth()
    {
        var allKeys = KeyList(
            "src/tenant/bookmark",
            "src/tenant/other/bookmark",
            "src/tenant/site/bookmark",
            "src/tenant/site/cursor");
        var storage = CreateStorage(CreateClient(allKeys));

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

    // ── TryGetAsync per-key path ──────────────────────────────────────────────

    [Fact]
    public async Task TryGetAsync_IssuesExactlyOneHttpCall()
    {
        var stateData = new Dictionary<string, string> { ["k"] = "\"v\"" };
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(FlatState(stateData), Encoding.UTF8, "application/json"),
                }));
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.TryGetAsync<string>("k");

        handlerMock.Protected().Verify(
            "SendAsync", Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    [Fact]
    public async Task TryGetAsync_AndDeleteAllAsync_IssueIndependentRequests()
    {
        // TryGetAsync issues one GET; DeleteAllAsync now issues one DELETE directly
        // (no GET to fetch state first), so total GET count should be 1.
        var stateData = new Dictionary<string, string>
        {
            ["prefix/a"] = "\"v\"",
            ["prefix/b"] = "\"v\"",
        };
        var getCount = 0;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns<HttpRequestMessage, CancellationToken>((req, _) =>
            {
                if (req.Method == HttpMethod.Get)
                {
                    getCount++;
                }

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(FlatState(stateData), Encoding.UTF8, "application/json"),
                });
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.TryGetAsync<string>("prefix/a");
        await storage.DeleteAllAsync("prefix");

        Assert.Equal(1, getCount);
    }

    // ── GetStateValueAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task GetStateValueAsync_ReturnsNull_WhenKeyAbsent()
    {
        var client = CreateClient("{}", HttpStatusCode.NotFound);

        var result = await client.GetStateValueAsync("scan-id", null, "missing", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetStateValueAsync_ThrowsStorageException_OnHttpError()
    {
        var client = CreateClient("{}", HttpStatusCode.InternalServerError);

        await Assert.ThrowsAsync<StateStorageException>(
            () => client.GetStateValueAsync("scan-id", null, "key", CancellationToken.None));
    }
}
