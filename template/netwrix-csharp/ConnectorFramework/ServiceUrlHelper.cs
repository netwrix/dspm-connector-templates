namespace Netwrix.ConnectorFramework;

/// <summary>
/// Resolves downstream service URLs using the same four-mode logic as the Python template.
/// </summary>
internal static class ServiceUrlHelper
{
    /// <summary>
    /// Resolves the URL for a named service.
    /// Priority:
    ///   1. Environment variable named <paramref name="envVarOverride"/> (e.g. "SAVE_DATA_FUNCTION")
    ///   2. Local mode (RUN_LOCAL=true): http://{serviceName}:8080
    ///   3. OpenFaaS (USE_OPENFAAS_GATEWAY=true): {OPENFAAS_GATEWAY}/[async-]function/{serviceName}
    ///   4. Kubernetes: http://{serviceName}.{namespace}.svc.cluster.local:{port}
    /// </summary>
    public static string Resolve(string envVarOverride, string defaultServiceName, int port = 80, bool useAsync = false)
    {
        var overrideUrl = Environment.GetEnvironmentVariable(envVarOverride);
        if (!string.IsNullOrEmpty(overrideUrl) && Uri.IsWellFormedUriString(overrideUrl, UriKind.Absolute))
        {
            return overrideUrl;
        }

        var serviceName = defaultServiceName;

        if (Environment.GetEnvironmentVariable(EnvironmentVariables.RunLocal) == "true")
        {
            return $"http://{serviceName}:8080";
        }

        if (Environment.GetEnvironmentVariable(EnvironmentVariables.UseOpenfaasGateway) == "true")
        {
            var gateway = Environment.GetEnvironmentVariable(EnvironmentVariables.OpenfaasGateway) ?? "http://gateway.openfaas:8080";
            var endpoint = useAsync ? "async-function" : "function";
            return $"{gateway}/{endpoint}/{serviceName}";
        }

        var ns = Environment.GetEnvironmentVariable(EnvironmentVariables.CommonFunctionsNamespace) ?? "access-analyzer";
        return $"http://{serviceName}.{ns}.svc.cluster.local:{port}";
    }
}
