using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class ConnectorStateClientRouteTests
{
    private record CapturedRequest(HttpMethod Method, string Path, string? Query, string Body);

    private static (ConnectorStateClient client, List<CapturedRequest> captured) CreateClient(
        HttpStatusCode statusCode = HttpStatusCode.OK,
        string responseBody = "{}")
    {
        var captured = new List<CapturedRequest>();

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Returns(async (HttpRequestMessage req, CancellationToken ct) =>
            {
                var body = req.Content is not null
                    ? await req.Content.ReadAsStringAsync(ct)
                    : string.Empty;
                captured.Add(new CapturedRequest(
                    req.Method,
                    req.RequestUri!.AbsolutePath,
                    req.RequestUri.Query,
                    body));
                return new HttpResponseMessage(statusCode)
                {
                    Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
                };
            });

        var client = new ConnectorStateClient(
            new HttpClient(handlerMock.Object) { BaseAddress = new Uri("http://connector-state/") },
            NullLogger<ConnectorStateClient>.Instance);

        return (client, captured);
    }

    // ── GetStateAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStateAsync_Sends_GET_To_ScanId_Path()
    {
        var (client, captured) = CreateClient(responseBody: "{\"k\":\"v\"}");
        await client.GetStateAsync("scan-1", null, CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Get, captured[0].Method);
        Assert.Equal("/scan-1", captured[0].Path);
    }

    [Fact]
    public async Task GetStateAsync_Returns_EmptyDict_On404()
    {
        var (client, _) = CreateClient(HttpStatusCode.NotFound);
        var result = await client.GetStateAsync("scan-1", null, CancellationToken.None);
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetStateAsync_Deserializes_Response_Dict()
    {
        var (client, _) = CreateClient(responseBody: "{\"key1\":\"val1\",\"key2\":\"val2\"}");
        var result = await client.GetStateAsync("scan-1", null, CancellationToken.None);
        Assert.Equal("val1", result["key1"]);
        Assert.Equal("val2", result["key2"]);
    }

    // ── ListKeysAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_Sends_GET_To_Keys_Path()
    {
        var (client, captured) = CreateClient(responseBody: "[]");
        await client.ListKeysAsync("scan-1", null, CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Get, captured[0].Method);
        Assert.Equal("/scan-1/keys", captured[0].Path);
    }

    [Fact]
    public async Task ListKeysAsync_Returns_EmptyArray_On404()
    {
        var (client, _) = CreateClient(HttpStatusCode.NotFound);
        var result = await client.ListKeysAsync("scan-1", null, CancellationToken.None);
        Assert.Empty(result);
    }

    [Fact]
    public async Task ListKeysAsync_Deserializes_Key_Array()
    {
        var (client, _) = CreateClient(responseBody: "[\"key1\",\"key2\",\"key3\"]");
        var result = await client.ListKeysAsync("scan-1", null, CancellationToken.None);
        Assert.Equal(["key1", "key2", "key3"], result);
    }

    // ── GetStateValueAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task GetStateValueAsync_Sends_GET_To_Key_Path()
    {
        var (client, captured) = CreateClient(responseBody: "{\"mykey\":\"myvalue\"}");
        await client.GetStateValueAsync("scan-1", null, "mykey", CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Get, captured[0].Method);
        Assert.Equal("/scan-1/keys/mykey", captured[0].Path);
    }

    [Fact]
    public async Task GetStateValueAsync_Returns_Null_On404()
    {
        var (client, _) = CreateClient(HttpStatusCode.NotFound);
        var result = await client.GetStateValueAsync("scan-1", null, "mykey", CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task GetStateValueAsync_Returns_Value_From_Response()
    {
        var (client, _) = CreateClient(responseBody: "{\"mykey\":\"myvalue\"}");
        var result = await client.GetStateValueAsync("scan-1", null, "mykey", CancellationToken.None);
        Assert.Equal("myvalue", result);
    }

    [Fact]
    public async Task GetStateValueAsync_Escapes_Key_In_Path()
    {
        var (client, captured) = CreateClient(responseBody: "{\"my/key\":\"v\"}");
        await client.GetStateValueAsync("scan-1", null, "my/key", CancellationToken.None);
        Assert.Equal("/scan-1/keys/my%2Fkey", captured[0].Path);
    }

    // ── PostStateAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task PostStateAsync_Sends_POST_To_ScanId_Path()
    {
        var (client, captured) = CreateClient();
        await client.PostStateAsync("scan-1", null, new Dictionary<string, string> { ["k"] = "v" }, CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Post, captured[0].Method);
        Assert.Equal("/scan-1", captured[0].Path);
    }

    [Fact]
    public async Task PostStateAsync_Sends_Data_As_Json_Body()
    {
        var (client, captured) = CreateClient();
        await client.PostStateAsync("scan-1", null, new Dictionary<string, string> { ["key1"] = "val1" }, CancellationToken.None);
        Assert.Contains("\"key1\"", captured[0].Body);
        Assert.Contains("\"val1\"", captured[0].Body);
    }

    [Fact]
    public async Task PostStateAsync_Does_Not_Include_ScanId_In_Body()
    {
        var (client, captured) = CreateClient();
        await client.PostStateAsync("scan-1", null, new Dictionary<string, string> { ["k"] = "v" }, CancellationToken.None);
        Assert.DoesNotContain("scanId", captured[0].Body);
    }

    // ── DeleteManyAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteManyAsync_Sends_DELETE_To_Keys_Path()
    {
        var (client, captured) = CreateClient();
        await client.DeleteManyAsync("scan-1", null, ["key1", "key2"], CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Delete, captured[0].Method);
        Assert.Equal("/scan-1/keys", captured[0].Path);
    }

    [Fact]
    public async Task DeleteManyAsync_Sends_Names_As_Json_Array_Body()
    {
        var (client, captured) = CreateClient();
        await client.DeleteManyAsync("scan-1", null, ["key1", "key2"], CancellationToken.None);
        Assert.Contains("\"key1\"", captured[0].Body);
        Assert.Contains("\"key2\"", captured[0].Body);
    }

    [Fact]
    public async Task DeleteManyAsync_Sends_No_Request_When_Names_Empty()
    {
        var (client, captured) = CreateClient();
        await client.DeleteManyAsync("scan-1", null, [], CancellationToken.None);
        Assert.Empty(captured);
    }

    [Fact]
    public async Task DeleteManyAsync_Treats_404_As_Success()
    {
        var (client, _) = CreateClient(HttpStatusCode.NotFound);
        await client.DeleteManyAsync("scan-1", null, ["key1"], CancellationToken.None);
        // no exception thrown
    }

    // ── DeleteByPrefixAsync ──────────────────────────────────────────────────

    [Fact]
    public async Task DeleteByPrefixAsync_EmptyPrefix_Sends_DELETE_To_ScanId_Path()
    {
        var (client, captured) = CreateClient();
        await client.DeleteByPrefixAsync("scan-1", null, "", CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Delete, captured[0].Method);
        Assert.Equal("/scan-1", captured[0].Path);
        Assert.Equal(string.Empty, captured[0].Query);
    }

    [Fact]
    public async Task DeleteByPrefixAsync_WithPrefix_Sends_DELETE_To_Keys_Path_With_Query()
    {
        var (client, captured) = CreateClient();
        await client.DeleteByPrefixAsync("scan-1", null, "myprefix", CancellationToken.None);
        Assert.Single(captured);
        Assert.Equal(HttpMethod.Delete, captured[0].Method);
        Assert.Equal("/scan-1/keys", captured[0].Path);
        Assert.Contains("prefix=myprefix", captured[0].Query);
    }

    [Fact]
    public async Task DeleteByPrefixAsync_Treats_404_As_Success()
    {
        var (client, _) = CreateClient(HttpStatusCode.NotFound);
        await client.DeleteByPrefixAsync("scan-1", null, "prefix", CancellationToken.None);
        // no exception thrown
    }

    // ── Error handling ───────────────────────────────────────────────────────

    [Fact]
    public async Task GetStateAsync_Throws_StateStorageException_On_500()
    {
        var (client, _) = CreateClient(HttpStatusCode.InternalServerError);
        await Assert.ThrowsAsync<StateStorageException>(
            () => client.GetStateAsync("scan-1", null, CancellationToken.None));
    }

    [Fact]
    public async Task PostStateAsync_Throws_StateStorageException_On_500()
    {
        var (client, _) = CreateClient(HttpStatusCode.InternalServerError);
        await Assert.ThrowsAsync<StateStorageException>(
            () => client.PostStateAsync("scan-1", null, new Dictionary<string, string> { ["k"] = "v" }, CancellationToken.None));
    }

    [Fact]
    public async Task DeleteManyAsync_Throws_StateStorageException_On_500()
    {
        var (client, _) = CreateClient(HttpStatusCode.InternalServerError);
        await Assert.ThrowsAsync<StateStorageException>(
            () => client.DeleteManyAsync("scan-1", null, ["key1"], CancellationToken.None));
    }
}
