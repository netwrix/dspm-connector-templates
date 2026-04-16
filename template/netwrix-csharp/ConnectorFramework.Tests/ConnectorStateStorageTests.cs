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

    private static string StateResponse(Dictionary<string, string> data)
        => JsonSerializer.Serialize(new { success = true, data });

    private static string EmptyStateResponse()
        => JsonSerializer.Serialize(new { success = true, data = new Dictionary<string, string>() });

    // ── TryGetAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task TryGetAsync_ReturnsNotFound_WhenKeyAbsent()
    {
        var storage = CreateStorage(CreateClient(EmptyStateResponse()));

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
        var storage = CreateStorage(CreateClient(StateResponse(stateData)));

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
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        var deleted = await storage.DeleteAsync("target");

        Assert.True(deleted);
        Assert.Equal(HttpMethod.Delete, deleteMethod);
        Assert.NotNull(deleteUrl);
        Assert.Contains("name=target", deleteUrl);
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
    public async Task DeleteAllAsync_IssuesDeleteForPrefixMatchingKeys()
    {
        var stateData = new Dictionary<string, string>
        {
            ["source/abc/bookmark"] = "\"v1\"",
            ["source/abc/cursor"] = "\"v2\"",
            ["other/key"] = "\"v3\"",
        };
        var deleteRequests = new List<string>();
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
                deleteRequests.Add(req.RequestUri!.ToString());
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.DeleteAllAsync("source/abc");

        Assert.Single(deleteRequests);
        var deleteUrl = deleteRequests[0];
        Assert.True(deleteUrl.Contains("bookmark") && deleteUrl.Contains("cursor"),
            $"Expected both bookmark and cursor in DELETE url: {deleteUrl}");
        Assert.DoesNotContain("other%2Fkey", deleteUrl);
        Assert.DoesNotContain("other/key", deleteUrl);
    }

    [Fact]
    public async Task DeleteAllAsync_BatchesDeleteRequests_WhenUrlLengthWouldExceedLimit()
    {
        // ConnectorStateClient.DeleteManyAsync batches by URL length (MaxDeleteQueryLength = 4,000)
        // rather than by a fixed key count. This prevents UriFormatException for long key names
        // and respects proxy URL size limits.
        //
        // Key format: "source/abc/item-NNNNNN" (22 chars, URL-encoded to 26 chars due to '/' → '%2F').
        // Per-key query segment: "&name=" (6) + 26 = 32 chars.
        // Base: "?scanId=scan-test" = 18 chars. Available per batch: 4,000 - 18 = 3,982.
        // Keys per batch: floor(3,982 / 32) = 124. For 300 keys: ceil(300 / 124) = 3 batches.
        const int keyCount = 300;
        const string prefix = "source/abc";

        var stateData = Enumerable.Range(0, keyCount)
            .ToDictionary(i => $"{prefix}/item-{i:D6}", _ => "\"v\"");

        var deleteRequests = new List<string>();
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
                deleteRequests.Add(req.RequestUri!.ToString());
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.DeleteAllAsync(prefix);

        Assert.Equal(3, deleteRequests.Count);

        // No single batch URL's query portion should exceed MaxDeleteQueryLength
        const string baseUrl = "http://connector-state/";
        foreach (var url in deleteRequests)
        {
            var queryLength = url.Length - baseUrl.Length;
            Assert.True(
                queryLength <= ConnectorStateClient.MaxDeleteQueryLength,
                $"Batch query exceeded {ConnectorStateClient.MaxDeleteQueryLength} chars ({queryLength}): {url[..Math.Min(200, url.Length)]}");
        }

        // Every key must appear in exactly one batch
        var allDeletedKeys = deleteRequests
            .SelectMany(url => url.Split('&')
                .Where(p => p.StartsWith("name=", StringComparison.Ordinal))
                .Select(p => Uri.UnescapeDataString(p["name=".Length..])))
            .ToHashSet();
        Assert.Equal(keyCount, allDeletedKeys.Count);
        Assert.All(stateData.Keys, k => Assert.Contains(k, allDeletedKeys));
    }

    [Fact]
    public async Task DeleteAllAsync_CompletesSafely_WhenTotalUrlWouldExceedNetUriLimit()
    {
        // Without URL-length-based batching, a single DELETE with these 100 keys would produce
        // a query string of ~72,018 chars, exceeding .NET's ~65,519-char URI limit and throwing
        // System.UriFormatException: Invalid URI: The Uri string is too long.
        //
        // Key format: "source/abc/" (11 chars) + 694 'a's + 5-digit index = 710 chars.
        // URL-encoded: "source%2Fabc%2F" (15) + 694 + 5 = 714 chars.
        // Per-key query segment: "&name=" (6) + 714 = 720 chars.
        // 100 keys unbatched: 18 + 100 × 720 = 72,018 chars → UriFormatException.
        // With MaxDeleteQueryLength = 4,000: floor((4,000-18)/720) = 5 keys/batch → 20 batches.
        const int keyCount = 100;
        const string prefix = "source/abc";

        var stateData = Enumerable.Range(0, keyCount)
            .ToDictionary(i => $"{prefix}/{new string('a', 694)}{i:D5}", _ => "\"v\"");

        var deleteRequests = new List<string>();
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
                deleteRequests.Add(req.RequestUri!.ToString());
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            });
        var storage = CreateStorage(CreateClient(handlerMock.Object));

        await storage.DeleteAllAsync(prefix);

        // Completed without UriFormatException — multiple batches were required
        Assert.True(deleteRequests.Count > 1, "Expected more than one DELETE batch for long-key workload");

        // Every key must appear in exactly one batch
        var allDeletedKeys = deleteRequests
            .SelectMany(url => url.Split('&')
                .Where(p => p.StartsWith("name=", StringComparison.Ordinal))
                .Select(p => Uri.UnescapeDataString(p["name=".Length..])))
            .ToHashSet();
        Assert.Equal(keyCount, allDeletedKeys.Count);
        Assert.All(stateData.Keys, k => Assert.Contains(k, allDeletedKeys));
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
        var storage = CreateStorage(CreateClient(StateResponse(stateData)));

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
        var stateData = new Dictionary<string, string>
        {
            ["src/tenant/site/bookmark"] = "\"v\"",
            ["src/tenant/site/cursor"] = "\"v\"",
            ["src/tenant/other/bookmark"] = "\"v\"",
            ["src/tenant/bookmark"] = "\"v\"", // depth=1 from src/tenant
        };
        var storage = CreateStorage(CreateClient(StateResponse(stateData)));

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
