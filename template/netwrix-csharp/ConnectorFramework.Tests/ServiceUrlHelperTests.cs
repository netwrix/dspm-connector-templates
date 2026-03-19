using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

public class ServiceUrlHelperTests : IDisposable
{
    private readonly List<string> _envVarsToClean = new();

    private void SetEnv(string name, string? value)
    {
        _envVarsToClean.Add(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose()
    {
        foreach (var name in _envVarsToClean)
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    // ── Env var override ─────────────────────────────────────────────────────

    [Fact]
    public void Resolve_ReturnsOverrideUrl_WhenAbsoluteUri()
    {
        SetEnv("APP_TEST", "http://my-service:9090");
        var result = ServiceUrlHelper.Resolve("APP_TEST", "my-service");
        Assert.Equal("http://my-service:9090", result);
    }

    [Fact]
    public void Resolve_IgnoresOverride_WhenBareServiceName()
    {
        SetEnv("APP_TEST", "my-service");
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        SetEnv("COMMON_FUNCTIONS_NAMESPACE", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST", "my-service");
        Assert.Equal("http://my-service.access-analyzer.svc.cluster.local:80", result);
    }

    [Fact]
    public void Resolve_IgnoresOverride_WhenEmptyEnvVar()
    {
        SetEnv("APP_TEST", "");
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        SetEnv("COMMON_FUNCTIONS_NAMESPACE", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST", "my-service");
        Assert.Equal("http://my-service.access-analyzer.svc.cluster.local:80", result);
    }

    [Fact]
    public void Resolve_IgnoresOverride_WhenEnvVarNotSet()
    {
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        SetEnv("COMMON_FUNCTIONS_NAMESPACE", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service");
        Assert.Equal("http://my-service.access-analyzer.svc.cluster.local:80", result);
    }

    // ── RUN_LOCAL ────────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_ReturnsLocalUrl_WhenRunLocalTrue()
    {
        SetEnv("RUN_LOCAL", "true");
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service");
        Assert.Equal("http://my-service:8080", result);
    }

    // ── OpenFaaS ─────────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_ReturnsOpenfaasUrl_WhenUseOpenfaasGatewayTrue()
    {
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", "true");
        SetEnv("OPENFAAS_GATEWAY", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service");
        Assert.Equal("http://gateway.openfaas:8080/function/my-service", result);
    }

    [Fact]
    public void Resolve_ReturnsAsyncOpenfaasUrl_WhenUseAsyncTrue()
    {
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", "true");
        SetEnv("OPENFAAS_GATEWAY", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service", useAsync: true);
        Assert.Equal("http://gateway.openfaas:8080/async-function/my-service", result);
    }

    // ── Kubernetes ───────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_ReturnsKubernetesFqdn_WhenNoFlagsSet()
    {
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        SetEnv("COMMON_FUNCTIONS_NAMESPACE", null);
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service");
        Assert.Equal("http://my-service.access-analyzer.svc.cluster.local:80", result);
    }

    [Fact]
    public void Resolve_UsesCustomNamespace_WhenCommonFunctionsNamespaceSet()
    {
        SetEnv("RUN_LOCAL", null);
        SetEnv("USE_OPENFAAS_GATEWAY", null);
        SetEnv("COMMON_FUNCTIONS_NAMESPACE", "my-ns");
        var result = ServiceUrlHelper.Resolve("APP_TEST_UNSET_XYZ", "my-service");
        Assert.Equal("http://my-service.my-ns.svc.cluster.local:80", result);
    }
}
