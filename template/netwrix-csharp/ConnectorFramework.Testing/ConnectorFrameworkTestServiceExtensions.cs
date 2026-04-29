using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Netwrix.ConnectorFramework;
using Netwrix.Overlord.Sdk.Orchestration;

namespace Netwrix.ConnectorFramework.Testing;

/// <summary>
/// Extension methods for registering ConnectorFramework scoped services in connector test projects.
/// </summary>
public static class ConnectorFrameworkTestServiceExtensions
{
    /// <summary>
    /// Registers the ConnectorFramework scoped services that <c>Program.cs</c> wires up at runtime,
    /// so connector test projects can invoke <c>Handler.HandleJobAsync</c> or
    /// <c>Handler.RunScanAsync</c> without referencing internal types directly.
    /// </summary>
    /// <remarks>
    /// Callers must separately register:
    /// <list type="bullet">
    ///   <item><description><see cref="IStateStorage"/> (e.g. an in-memory implementation)</description></item>
    ///   <item><description><see cref="IRunStateStorageFactory"/></description></item>
    ///   <item><description><see cref="ICrawlRunOrchestrator"/> (real or mock)</description></item>
    ///   <item><description>Logging (<c>services.AddLogging()</c>)</description></item>
    ///   <item><description>Configuration (<c>services.AddSingleton&lt;IConfiguration&gt;(...)</c>)</description></item>
    ///   <item><description><c>IHttpClientFactory</c></description></item>
    /// </list>
    /// </remarks>
    public static IServiceCollection AddConnectorFrameworkTestServices(
        this IServiceCollection services)
    {
        // Internal type: not directly referenceable from connector test projects.
        services.AddScoped<RequestDataHolder>();
        services.AddScoped<ConnectorRequestData>(
            sp => sp.GetRequiredService<RequestDataHolder>().Data);

        // ConnectorStateClient is sealed — create a no-op instance.
        // ScanExecutionId=null makes UpdateExecutionAsync a no-op, so the HttpClient is never called.
        services.AddScoped(sp =>
            new ConnectorStateClient(
                new HttpClient(),
                sp.GetRequiredService<ILoggerFactory>().CreateLogger<ConnectorStateClient>()));

        services.AddScoped<FunctionContext>();
        services.AddScoped<IScanProgress>(sp => sp.GetRequiredService<FunctionContext>());
        services.AddScoped<IScanWriter>(sp => sp.GetRequiredService<FunctionContext>());

        services.AddScoped<AACorePlatformFacade>();
        services.AddScoped<AACrawlTaskCorePlatformFacade>(sp =>
            new AACrawlTaskCorePlatformFacade(
                sp.GetRequiredService<AACorePlatformFacade>(),
                sp.GetRequiredService<IScanProgress>(),
                sp.GetRequiredService<ILoggerFactory>()
                    .CreateLogger<AACrawlTaskCorePlatformFacade>()));
        services.AddSingleton<AACrawlTaskFacadeHolder>();

        services.AddOptions<CrawlRunOrchestratorOptions>();

        return services;
    }
}
