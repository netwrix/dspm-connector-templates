using Netwrix.Overlord.Sdk.Orchestration;

namespace Netwrix.ConnectorFramework;

public static class CrawlRunOrchestratorServiceExtensions
{
    /// <summary>
    /// Applies <see cref="CrawlRunOrchestratorOptions"/> overrides from environment variables.
    /// Call via <c>PostConfigure</c> so environment variables win over code defaults.
    /// </summary>
    /// <remarks>
    /// Recognised variables: MAX_WORKERS, MAX_CONCURRENCY_PER_SOURCE, MAX_ATTEMPTS,
    /// MAX_AUTH_RETRY_ATTEMPTS, MAX_HASH_MISMATCH_ATTEMPTS, MAX_QUEUE_DEPTH,
    /// CONFIG_CACHE_TTL_MINUTES.
    /// </remarks>
    public static void ApplyOrchestratorEnvVarOverrides(CrawlRunOrchestratorOptions opts)
    {
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_WORKERS"), out var v))
            opts.MaxWorkers = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_CONCURRENCY_PER_SOURCE"), out v))
            opts.MaxConcurrencyPerSource = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_ATTEMPTS"), out v))
            opts.MaxAttempts = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_AUTH_RETRY_ATTEMPTS"), out v))
            opts.MaxAuthRetryAttempts = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_HASH_MISMATCH_ATTEMPTS"), out v))
            opts.MaxHashMismatchAttempts = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("MAX_QUEUE_DEPTH"), out v))
            opts.MaxQueueDepth = v;
        if (int.TryParse(Environment.GetEnvironmentVariable("CONFIG_CACHE_TTL_MINUTES"), out v))
            opts.ConfigCacheTtl = TimeSpan.FromMinutes(v);
    }
}
