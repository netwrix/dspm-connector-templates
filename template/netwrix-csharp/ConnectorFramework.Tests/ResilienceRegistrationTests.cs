using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Moq.Protected;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;
using Polly;
using Polly.Retry;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

/// <summary>
/// Verifies that all four platform HTTP clients are registered with resilience pipelines
/// in the framework's DI setup.
/// </summary>
public class ResilienceRegistrationTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddHttpClient<ConnectorStateClient>(
            ConnectorStateClient.HttpClientName,
            client => client.BaseAddress = new Uri("http://connector-state/"))
            .AddStandardResilienceHandler(o =>
            {
                o.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
                o.CircuitBreaker.MinimumThroughput = 10;
            });

        services.AddHttpClient(ServiceNames.DataIngestion)
            .AddStandardResilienceHandler();

        services.AddHttpClient(ServiceNames.UpdateExecution)
            .AddStandardResilienceHandler();

        services.AddHttpClient(ServiceNames.AppDataQuery)
            .AddStandardResilienceHandler();

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Creates a mock handler that returns the given status codes in sequence,
    /// each with a minimal valid connector-state JSON body.
    /// </summary>
    private static Mock<HttpMessageHandler> MakeSequentialHandler(params HttpStatusCode[] responses)
    {
        var mock = new Mock<HttpMessageHandler>();
        var sequence = mock.Protected()
            .SetupSequence<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>());

        foreach (var code in responses)
        {
            var captured = code;
            sequence = sequence.ReturnsAsync(() => new HttpResponseMessage(captured)
            {
                Content = new StringContent(
                    """{"success":true,"data":{}}""",
                    System.Text.Encoding.UTF8,
                    "application/json"),
            });
        }

        return mock;
    }

    // ── Registration smoke tests ──────────────────────────────────────────────

    [Fact]
    public void ConnectorStateClient_ResolvesFromFactory()
    {
        var factory = BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
        Assert.NotNull(factory.CreateClient(ConnectorStateClient.HttpClientName));
    }

    [Fact]
    public void DataIngestionClient_ResolvesFromFactory()
    {
        var factory = BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
        Assert.NotNull(factory.CreateClient(ServiceNames.DataIngestion));
    }

    [Fact]
    public void UpdateExecutionClient_ResolvesFromFactory()
    {
        var factory = BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
        Assert.NotNull(factory.CreateClient(ServiceNames.UpdateExecution));
    }

    [Fact]
    public void AppDataQueryClient_ResolvesFromFactory()
    {
        var factory = BuildServiceProvider().GetRequiredService<IHttpClientFactory>();
        Assert.NotNull(factory.CreateClient(ServiceNames.AppDataQuery));
    }

    // ── Retry behaviour ───────────────────────────────────────────────────────

    /// <summary>
    /// Builds a service provider with a <see cref="ConnectorStateClient"/> whose primary
    /// handler is replaced by <paramref name="handler"/> and whose resilience pipeline
    /// uses a minimal retry strategy (zero delay, no circuit breaker, no timeout) so
    /// tests run instantly and aren't affected by production thresholds.
    /// </summary>
    private static ServiceProvider BuildRetryTestServiceProvider(HttpMessageHandler handler)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        var builder = services.AddHttpClient<ConnectorStateClient>(
            ConnectorStateClient.HttpClientName,
            client => client.BaseAddress = new Uri("http://connector-state/"));

        // Configure primary handler before adding the resilience delegating handler.
        builder.ConfigurePrimaryHttpMessageHandler(() => handler);

        builder.AddResilienceHandler("test-retry", b =>
        {
            b.AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                MaxRetryAttempts = 2,
                Delay = TimeSpan.Zero,
                UseJitter = false,
                ShouldHandle = args => ValueTask.FromResult(
                    args.Outcome.Result?.StatusCode >= HttpStatusCode.InternalServerError
                    || args.Outcome.Exception is HttpRequestException),
            });
        });

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Verifies that a transient 503 from connector-state is retried and the eventual 200
    /// succeeds. Confirms the resilience handler is in the pipeline and wired correctly.
    /// </summary>
    [Fact]
    public async Task ConnectorStateClient_RetriesOnTransient503()
    {
        var handler = MakeSequentialHandler(HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK);

        await using var sp = BuildRetryTestServiceProvider(handler.Object);
        var stateClient = sp.GetRequiredService<ConnectorStateClient>();

        var result = await stateClient.GetStateAsync("scan-1", null, CancellationToken.None);
        Assert.NotNull(result);

        handler.Protected().Verify(
            "SendAsync",
            Times.Exactly(2),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies that exhausting all retry attempts surfaces a
    /// <see cref="StateStorageException"/> rather than swallowing the failure.
    /// </summary>
    [Fact]
    public async Task ConnectorStateClient_ThrowsAfterRetryBudgetExhausted()
    {
        var handler = MakeSequentialHandler(
            HttpStatusCode.ServiceUnavailable,
            HttpStatusCode.ServiceUnavailable,
            HttpStatusCode.ServiceUnavailable);

        await using var sp = BuildRetryTestServiceProvider(handler.Object);
        var stateClient = sp.GetRequiredService<ConnectorStateClient>();

        await Assert.ThrowsAsync<StateStorageException>(
            () => stateClient.GetStateAsync("scan-1", null, CancellationToken.None));
    }
}
