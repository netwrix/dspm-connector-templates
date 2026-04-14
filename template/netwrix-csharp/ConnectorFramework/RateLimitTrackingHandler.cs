using System.Net;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Delegating handler that counts HTTP 429 (Too Many Requests) responses received
/// from source systems and records them as <see cref="ConnectorMetrics.SourceRateLimits"/>.
///
/// Internal cluster URLs (*.svc.cluster.local, localhost, 127.0.0.1) are excluded
/// so that rate-limit responses from the connector-api or other internal services
/// do not inflate the source-system counter.
/// </summary>
internal sealed class RateLimitTrackingHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.TooManyRequests
            && !IsInternalServiceUrl(request.RequestUri))
        {
            ConnectorMetrics.SourceRateLimits.Add(1);
        }

        return response;
    }

    private static bool IsInternalServiceUrl(Uri? uri)
    {
        if (uri is null)
        {
            return false;
        }

        var host = uri.Host;
        return host.EndsWith(".svc.cluster.local", StringComparison.OrdinalIgnoreCase)
            || host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || host.Equals("127.0.0.1", StringComparison.Ordinal);
    }
}
