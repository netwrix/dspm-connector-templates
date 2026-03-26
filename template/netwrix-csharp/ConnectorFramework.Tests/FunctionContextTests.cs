using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Netwrix.Overlord.Sdk.Core.Storage;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class FunctionContextTests
{
    private static ConnectorRequestData MakeRequest(
        string? scanId = "scan-abc",
        string? execId = "exec-xyz")
        => new("POST", "/connector/access_scan", new Dictionary<string, string>(), null,
            new ExecutionContext(ScanId: scanId, ScanExecutionId: execId, SourceId: null, SourceType: null, SourceVersion: null, FunctionType: null));

    private static FunctionContext CreateContext(
        IHttpClientFactory? factory = null,
        string? scanId = "scan-abc",
        string? execId = "exec-xyz",
        IStateStorage? stateStorage = null)
    {
        factory ??= Mock.Of<IHttpClientFactory>();
        stateStorage ??= Mock.Of<IStateStorage>();
        return new FunctionContext(
            MakeRequest(scanId, execId),
            new ConfigurationBuilder().Build(),
            factory,
            NullLogger<FunctionContext>.Instance,
            NullLoggerFactory.Instance,
            stateStorage);
    }

    private static async IAsyncEnumerable<string> ToAsyncKeys(params string[] keys)
    {
        foreach (var k in keys)
        {
            yield return k;
        }

        await Task.CompletedTask;
    }

    private static (Mock<HttpMessageHandler> HandlerMock, IHttpClientFactory Factory) CreateFactory(
        string responseBody,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
            });

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);
        return (handlerMock, factoryMock.Object);
    }

    // ── UpdateExecutionAsync ─────────────────────────────────────────────────

    [Fact]
    public async Task UpdateExecutionAsync_SendsTotalObjectsAndCompletedObjects_WhenSet()
    {
        byte[]? body = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                body = await req.Content!.ReadAsByteArrayAsync();
            })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, execId: "exec-1");
        await ctx.UpdateExecutionAsync(totalObjects: 100, completedObjects: 50);

        Assert.NotNull(body);
        var json = Encoding.UTF8.GetString(body!);
        Assert.Contains("\"totalObjects\"", json);
        Assert.Contains("100", json);
        Assert.Contains("\"completedObjects\"", json);
        Assert.Contains("50", json);
    }

    [Fact]
    public async Task UpdateExecutionAsync_DoesNotSendTotalObjects_WhenNull()
    {
        byte[]? body = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                body = await req.Content!.ReadAsByteArrayAsync();
            })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, execId: "exec-1");
        await ctx.UpdateExecutionAsync(status: "running");

        Assert.NotNull(body);
        var json = Encoding.UTF8.GetString(body!);
        Assert.DoesNotContain("totalObjects", json);
        Assert.DoesNotContain("completedObjects", json);
    }

    [Fact]
    public async Task UpdateExecutionAsync_SkipsWhenScanExecutionIdIsNull()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        await using var ctx = CreateContext(factoryMock.Object, execId: null);
        await ctx.UpdateExecutionAsync(status: "running"); // should not throw or call HTTP
        factoryMock.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }

    // ── GetConnectorStateAsync ───────────────────────────────────────────────

    [Fact]
    public async Task GetConnectorStateAsync_ReturnsDictionaryFromStorage()
    {
        var storageMock = new Mock<IStateStorage>();
        storageMock
            .Setup(s => s.ListAllKeysAsync("", It.IsAny<CancellationToken>()))
            .Returns(ToAsyncKeys("key1"));
        storageMock
            .Setup(s => s.TryGetAsync<string>("key1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TryGetResult<string>("val1", null));

        await using var ctx = CreateContext(scanId: "scan-42", stateStorage: storageMock.Object);
        var result = await ctx.GetConnectorStateAsync();

        Assert.NotNull(result);
        Assert.Equal("val1", result!["key1"]);
    }

    [Fact]
    public async Task GetConnectorStateAsync_ReturnsNull_WhenScanIdIsNull()
    {
        var storageMock = new Mock<IStateStorage>();
        await using var ctx = CreateContext(scanId: null, stateStorage: storageMock.Object);
        var result = await ctx.GetConnectorStateAsync();
        Assert.Null(result);
        storageMock.Verify(s => s.ListAllKeysAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── SetConnectorStateAsync ───────────────────────────────────────────────

    [Fact]
    public async Task SetConnectorStateAsync_CallsSetAsyncForEachKey()
    {
        var storageMock = new Mock<IStateStorage>();
        storageMock
            .Setup(s => s.SetAsync<object>(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await using var ctx = CreateContext(scanId: "scan-42", stateStorage: storageMock.Object);
        await ctx.SetConnectorStateAsync(new Dictionary<string, object?> { ["cursor"] = "abc" });

        storageMock.Verify(s => s.SetAsync<object>("cursor", "abc", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SetConnectorStateAsync_SkipsWhenScanIdIsNull()
    {
        var storageMock = new Mock<IStateStorage>();
        await using var ctx = CreateContext(scanId: null, stateStorage: storageMock.Object);
        await ctx.SetConnectorStateAsync(new Dictionary<string, object?> { ["x"] = "y" });
        storageMock.Verify(s => s.SetAsync<object>(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── DeleteConnectorStateAsync ────────────────────────────────────────────

    [Fact]
    public async Task DeleteConnectorStateAsync_CallsDeleteAllAsync_WhenNamesIsNull()
    {
        var storageMock = new Mock<IStateStorage>();
        storageMock
            .Setup(s => s.DeleteAllAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await using var ctx = CreateContext(scanId: "scan-42", stateStorage: storageMock.Object);
        await ctx.DeleteConnectorStateAsync();

        storageMock.Verify(s => s.DeleteAllAsync("", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DeleteConnectorStateAsync_CallsDeleteAsyncForEachName()
    {
        var storageMock = new Mock<IStateStorage>();
        storageMock
            .Setup(s => s.DeleteAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await using var ctx = CreateContext(scanId: "scan-42", stateStorage: storageMock.Object);
        await ctx.DeleteConnectorStateAsync(new[] { "key1", "key2" });

        storageMock.Verify(s => s.DeleteAsync("key1", It.IsAny<CancellationToken>()), Times.Once);
        storageMock.Verify(s => s.DeleteAsync("key2", It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── GetPriorExecutionAsync ───────────────────────────────────────────────

    // scanExecutionId must be a valid GUID — the framework validates format before querying.
    private const string PriorExecId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsExecution_WhenFound()
    {
        var responseBody = JsonSerializer.Serialize(new
        {
            success = true,
            data = new[]
            {
                new { id = PriorExecId, status = "paused", completed_objects = 42 },
            },
        });

        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync(PriorExecId);

        Assert.NotNull(result);
        Assert.Equal(PriorExecId, result!.Id);
        Assert.Equal("paused", result.Status);
        Assert.Equal(42, result.CompletedObjects);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsNull_WhenNoDataFound()
    {
        var responseBody = JsonSerializer.Serialize(new { success = true, data = Array.Empty<object>() });
        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync(PriorExecId);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsNull_WhenCompletedObjectsIsZero()
    {
        var responseBody = JsonSerializer.Serialize(new
        {
            success = true,
            data = new[]
            {
                new { id = PriorExecId, status = "paused", completed_objects = 0 },
            },
        });

        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync(PriorExecId);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsNull_WhenIdIsNotAGuid()
    {
        // Non-GUID IDs must be rejected before issuing any HTTP request.
        await using var ctx = CreateContext();
        var result = await ctx.GetPriorExecutionAsync("not-a-guid");
        Assert.Null(result);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_SendsPostWithQuery()
    {
        byte[]? body = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                body = await req.Content!.ReadAsByteArrayAsync();
            })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { success = true, data = Array.Empty<object>() }),
                    Encoding.UTF8, "application/json"),
            });

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object);
        await ctx.GetPriorExecutionAsync(PriorExecId);

        Assert.NotNull(body);
        var json = Encoding.UTF8.GetString(body!);
        Assert.Contains("scan_executions", json);
        Assert.Contains(PriorExecId, json);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsNull_ForEmptyId()
    {
        await using var ctx = CreateContext();
        var result = await ctx.GetPriorExecutionAsync("");
        Assert.Null(result);
    }

    // ── GetObjectSuccessResponse ─────────────────────────────────────────────

    [Fact]
    public void GetObjectSuccessResponse_ReturnsBase64EncodedData()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var expected = Convert.ToBase64String(data);

        var response = FunctionContext.GetObjectSuccessResponse(data);
        var json = JsonSerializer.Serialize(response);

        Assert.Contains("200", json);
        Assert.Contains(expected, json);
    }

    [Fact]
    public void GetObjectSuccessResponse_EmptyArray_ReturnsEmptyBase64()
    {
        var response = FunctionContext.GetObjectSuccessResponse(Array.Empty<byte>());
        var json = JsonSerializer.Serialize(response);
        Assert.Contains("200", json);
        Assert.Contains(Convert.ToBase64String(Array.Empty<byte>()), json);
    }

    // ── SaveObject ───────────────────────────────────────────────────────────

    [Fact]
    public async Task SaveObject_DelegatesToGetTable()
    {
        var (_, factory) = CreateFactory("{}", HttpStatusCode.Accepted);
        await using var ctx = CreateContext(factory);

        ctx.SaveObject("my_table", new { x = 1 });

        // GetTable should have created a BatchManager for "my_table"
        var bm = ctx.GetTable("my_table");
        Assert.NotNull(bm);
    }

    // ── SECRET_MAPPINGS ──────────────────────────────────────────────────────

    [Fact]
    public void Secrets_SecretMappings_LogsWarning_WhenSecretNotFound()
    {
        // On test machines /var/secrets doesn't exist, so dict is empty.
        // SECRET_MAPPINGS references a non-existent secret → warning should be logged.
        var loggerMock = new Mock<ILogger<FunctionContext>>();
        loggerMock.Setup(x => x.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        Environment.SetEnvironmentVariable("SECRET_MAPPINGS", "myKey:nonExistentSecret");
        try
        {
            var ctx = new FunctionContext(
                MakeRequest(),
                new ConfigurationBuilder().Build(),
                Mock.Of<IHttpClientFactory>(),
                loggerMock.Object,
                NullLoggerFactory.Instance,
                Mock.Of<IStateStorage>());

            var secrets = ctx.Secrets;

            // The aliased key should not be in the dict since the secret file doesn't exist
            Assert.False(secrets.ContainsKey("myKey"));

            // A warning should have been logged
            loggerMock.Verify(
                x => x.Log(
                    LogLevel.Warning,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("nonExistentSecret")),
                    It.IsAny<Exception?>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.Once);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECRET_MAPPINGS", null);
        }
    }
}
