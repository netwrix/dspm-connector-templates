using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Netwrix.Overlord.Sdk.Orchestration;
using Xunit;

namespace Netwrix.ConnectorFramework.Tests;

// Process-level env vars mutated in these tests are not thread-safe across parallel runs.
// Run this collection sequentially to avoid flaky interference with other test classes.
[Collection("Sequential")]
public class OrchestratorOptionsTests
{
    private static IOptions<CrawlRunOrchestratorOptions> BuildOptions(Action<CrawlRunOrchestratorOptions>? seed = null)
    {
        var services = new ServiceCollection();
        var builder = services.AddOptions<CrawlRunOrchestratorOptions>();
        if (seed is not null)
            builder.Configure(seed);
        builder.PostConfigure(CrawlRunOrchestratorServiceExtensions.ApplyOrchestratorEnvVarOverrides);
        var sp = services.BuildServiceProvider();
        return sp.GetRequiredService<IOptions<CrawlRunOrchestratorOptions>>();
    }

    [Fact]
    public void MaxWorkers_DefaultPreserved_WhenEnvVarAbsent()
    {
        Environment.SetEnvironmentVariable("MAX_WORKERS", null);
        var opts = BuildOptions(o => o.MaxWorkers = 3).Value;
        Assert.Equal(3, opts.MaxWorkers);
    }

    [Fact]
    public void MaxWorkers_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_WORKERS", "10");
        try
        {
            var opts = BuildOptions(o => o.MaxWorkers = 3).Value;
            Assert.Equal(10, opts.MaxWorkers);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_WORKERS", null);
        }
    }

    [Fact]
    public void MaxConcurrencyPerSource_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_CONCURRENCY_PER_SOURCE", "6");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(6, opts.MaxConcurrencyPerSource);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_CONCURRENCY_PER_SOURCE", null);
        }
    }

    [Fact]
    public void MaxAttempts_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_ATTEMPTS", "7");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(7, opts.MaxAttempts);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_ATTEMPTS", null);
        }
    }

    [Fact]
    public void MaxAuthRetryAttempts_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_AUTH_RETRY_ATTEMPTS", "4");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(4, opts.MaxAuthRetryAttempts);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_AUTH_RETRY_ATTEMPTS", null);
        }
    }

    [Fact]
    public void MaxHashMismatchAttempts_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_HASH_MISMATCH_ATTEMPTS", "2");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(2, opts.MaxHashMismatchAttempts);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_HASH_MISMATCH_ATTEMPTS", null);
        }
    }

    [Fact]
    public void MaxQueueDepth_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("MAX_QUEUE_DEPTH", "500");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(500, opts.MaxQueueDepth);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_QUEUE_DEPTH", null);
        }
    }

    [Fact]
    public void ConfigCacheTtlMinutes_OverriddenByEnvVar()
    {
        Environment.SetEnvironmentVariable("CONFIG_CACHE_TTL_MINUTES", "45");
        try
        {
            var opts = BuildOptions().Value;
            Assert.Equal(TimeSpan.FromMinutes(45), opts.ConfigCacheTtl);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CONFIG_CACHE_TTL_MINUTES", null);
        }
    }

    [Fact]
    public void NonInteger_IsIgnored_DefaultPreserved()
    {
        Environment.SetEnvironmentVariable("MAX_WORKERS", "not-a-number");
        try
        {
            var opts = BuildOptions(o => o.MaxWorkers = 5).Value;
            Assert.Equal(5, opts.MaxWorkers);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MAX_WORKERS", null);
        }
    }
}
