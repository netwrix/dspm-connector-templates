using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Moq.Protected;
using Netwrix.Overlord.Sdk.Core.Exceptions;
using Polly.CircuitBreaker;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class ConnectorStateClientTests
{
    private static ConnectorStateClient CreateClientThrowing(Exception ex)
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(ex);
        return new ConnectorStateClient(
            new HttpClient(handlerMock.Object) { BaseAddress = new Uri("http://connector-state/") },
            NullLogger<ConnectorStateClient>.Instance);
    }

    [Fact]
    public async Task GetStateAsync_BrokenCircuit_ThrowsInfrastructureUnavailable()
    {
        var client = CreateClientThrowing(new BrokenCircuitException("circuit open"));

        var ex = await Assert.ThrowsAsync<InfrastructureUnavailableException>(
            () => client.GetStateAsync("scan-1", null, CancellationToken.None));

        Assert.Contains("connector-state", ex.Message);
    }

    [Fact]
    public async Task GetStateAsync_IsolatedCircuit_ThrowsInfrastructureUnavailable()
    {
        var client = CreateClientThrowing(new IsolatedCircuitException("circuit isolated"));

        await Assert.ThrowsAsync<InfrastructureUnavailableException>(
            () => client.GetStateAsync("scan-1", null, CancellationToken.None));
    }

    [Fact]
    public async Task PutStateAsync_BrokenCircuit_ThrowsInfrastructureUnavailable()
    {
        var client = CreateClientThrowing(new BrokenCircuitException("circuit open"));

        var ex = await Assert.ThrowsAsync<InfrastructureUnavailableException>(
            () => client.PutStateAsync("scan-1", null, new Dictionary<string, string>(), CancellationToken.None));

        Assert.Contains("connector-state", ex.Message);
    }

    [Fact]
    public async Task DeleteManyAsync_BrokenCircuit_ThrowsInfrastructureUnavailable()
    {
        var client = CreateClientThrowing(new BrokenCircuitException("circuit open"));

        var ex = await Assert.ThrowsAsync<InfrastructureUnavailableException>(
            () => client.DeleteManyAsync("scan-1", null, ["key1"], CancellationToken.None));

        Assert.Contains("connector-state", ex.Message);
    }
}
