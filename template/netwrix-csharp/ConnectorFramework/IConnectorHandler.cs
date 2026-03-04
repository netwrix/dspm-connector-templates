namespace Netwrix.ConnectorFramework;

/// <summary>
/// Contract that every connector handler must implement.
/// The framework discovers the single non-abstract implementation via reflection on the function assembly.
/// </summary>
public interface IConnectorHandler
{
    /// <summary>
    /// Optional: register connector-specific services into DI.
    /// Called before the host is built so the connector can add its own dependencies.
    /// </summary>
    void MapServices(IServiceCollection services) { }

    /// <summary>
    /// Optional (HTTP mode): map the connector's routes onto the ASP.NET Core application.
    /// Use Minimal API methods (app.MapGet, app.MapPost, etc.) to declare operations.
    /// Long-running operations should return 202 Accepted immediately and run in the background.
    /// Job-only connectors may leave this as the default no-op.
    /// </summary>
    void MapEndpoints(WebApplication app) { }

    /// <summary>
    /// Required (job mode): handle a single invocation directly, without an HTTP server.
    /// The framework calls this with the request data constructed from environment variables.
    /// </summary>
    Task<object> HandleJobAsync(ConnectorRequestData request, FunctionContext context, CancellationToken ct);
}
