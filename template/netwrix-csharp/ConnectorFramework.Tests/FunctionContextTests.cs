using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class FunctionContextTests
{
    private static ConnectorRequestData MakeRequest(
        string? scanId = "scan-abc",
        string? execId = "exec-xyz")
        => new("POST", "/connector/access_scan", new Dictionary<string, string>(), null, scanId, execId);

    private static FunctionContext CreateContext(
        IHttpClientFactory? factory = null,
        string? scanId = "scan-abc",
        string? execId = "exec-xyz")
    {
        factory ??= Mock.Of<IHttpClientFactory>();
        return new FunctionContext(
            MakeRequest(scanId, execId),
            new ConfigurationBuilder().Build(),
            factory,
            NullLogger<FunctionContext>.Instance,
            NullLoggerFactory.Instance);
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
    public async Task GetConnectorStateAsync_SendsGetWithScanId()
    {
        HttpRequestMessage? captured = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => { captured = req; })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { success = true, data = new { key1 = "val1" } }),
                    Encoding.UTF8, "application/json"),
            });

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, scanId: "scan-42");
        var result = await ctx.GetConnectorStateAsync();

        Assert.Equal(HttpMethod.Get, captured!.Method);
        Assert.Contains("scanId=scan-42", captured.RequestUri!.ToString());
        Assert.NotNull(result);
        Assert.Equal("val1", result!["key1"]);
    }

    [Fact]
    public async Task GetConnectorStateAsync_ReturnsNull_WhenScanIdIsNull()
    {
        await using var ctx = CreateContext(scanId: null);
        var result = await ctx.GetConnectorStateAsync();
        Assert.Null(result);
    }

    // ── SetConnectorStateAsync ───────────────────────────────────────────────

    [Fact]
    public async Task SetConnectorStateAsync_SendsPostWithScanIdAndData()
    {
        byte[]? body = null;
        HttpRequestMessage? captured = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
            {
                captured = req;
                body = await req.Content!.ReadAsByteArrayAsync();
            })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, scanId: "scan-42");
        await ctx.SetConnectorStateAsync(new Dictionary<string, object?> { ["cursor"] = "abc" });

        Assert.Equal(HttpMethod.Post, captured!.Method);
        Assert.NotNull(body);
        var json = Encoding.UTF8.GetString(body!);
        Assert.Contains("scan-42", json);
        Assert.Contains("cursor", json);
        Assert.Contains("abc", json);
    }

    [Fact]
    public async Task SetConnectorStateAsync_SkipsWhenScanIdIsNull()
    {
        var factoryMock = new Mock<IHttpClientFactory>();
        await using var ctx = CreateContext(factoryMock.Object, scanId: null);
        await ctx.SetConnectorStateAsync(new Dictionary<string, object?> { ["x"] = "y" });
        factoryMock.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
    }

    // ── DeleteConnectorStateAsync ────────────────────────────────────────────

    [Fact]
    public async Task DeleteConnectorStateAsync_SendsDeleteWithScanId()
    {
        HttpRequestMessage? captured = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => { captured = req; })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, scanId: "scan-42");
        await ctx.DeleteConnectorStateAsync();

        Assert.Equal(HttpMethod.Delete, captured!.Method);
        Assert.Contains("scanId=scan-42", captured.RequestUri!.ToString());
        Assert.DoesNotContain("name", captured.RequestUri!.ToString());
    }

    [Fact]
    public async Task DeleteConnectorStateAsync_IncludesNamesInQueryString()
    {
        HttpRequestMessage? captured = null;
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => { captured = req; })
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(handlerMock.Object);
        var factoryMock = new Mock<IHttpClientFactory>();
        factoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        await using var ctx = CreateContext(factoryMock.Object, scanId: "scan-42");
        await ctx.DeleteConnectorStateAsync(new[] { "key1", "key2" });

        var url = captured!.RequestUri!.ToString();
        // .NET Uri may keep [] unencoded or percent-encode them — accept both forms
        Assert.True(url.Contains("name%5B%5D=key1") || url.Contains("name[]=key1"), $"Expected name[]=key1 in: {url}");
        Assert.True(url.Contains("name%5B%5D=key2") || url.Contains("name[]=key2"), $"Expected name[]=key2 in: {url}");
    }

    // ── GetPriorExecutionAsync ───────────────────────────────────────────────

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsExecution_WhenFound()
    {
        var responseBody = JsonSerializer.Serialize(new
        {
            success = true,
            data = new[]
            {
                new { id = "exec-prior", status = "paused", completed_objects = 42 },
            },
        });

        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync("exec-prior");

        Assert.NotNull(result);
        Assert.Equal("exec-prior", result!.Id);
        Assert.Equal("paused", result.Status);
        Assert.Equal(42, result.CompletedObjects);
    }

    [Fact]
    public async Task GetPriorExecutionAsync_ReturnsNull_WhenNoDataFound()
    {
        var responseBody = JsonSerializer.Serialize(new { success = true, data = Array.Empty<object>() });
        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync("exec-prior");

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
                new { id = "exec-prior", status = "paused", completed_objects = 0 },
            },
        });

        var (_, factory) = CreateFactory(responseBody);
        await using var ctx = CreateContext(factory);

        var result = await ctx.GetPriorExecutionAsync("exec-prior");

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
        await ctx.GetPriorExecutionAsync("exec-prior-123");

        Assert.NotNull(body);
        var json = Encoding.UTF8.GetString(body!);
        Assert.Contains("scan_executions", json);
        Assert.Contains("exec-prior-123", json);
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
                NullLoggerFactory.Instance);

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
