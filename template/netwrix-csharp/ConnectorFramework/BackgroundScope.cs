using Microsoft.Extensions.DependencyInjection;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Holds a pre-captured ConnectorRequestData for injection into a DI scope that has no
/// active HTTP context (background Task.Run, job mode). Set-once per scope.
/// </summary>
internal sealed class RequestDataHolder
{
    private ConnectorRequestData? _data;

    internal bool IsSet => _data is not null;

    public ConnectorRequestData Data
    {
        get => _data ?? throw new InvalidOperationException(
            "RequestDataHolder.Data was not set before resolving FunctionContext. " +
            "Use IServiceScopeFactory.CreateBackgroundScope(requestData) for background scopes.");
        set
        {
            if (_data is not null)
                throw new InvalidOperationException(
                    "RequestDataHolder.Data may only be set once per scope.");
            _data = value;
        }
    }
}

/// <summary>
/// Extension methods for creating background DI scopes pre-seeded with
/// a captured ConnectorRequestData so FunctionContext resolves correctly
/// outside of an active HTTP request.
/// </summary>
public static class ServiceScopeFactoryExtensions
{
    /// <summary>
    /// Creates an async DI scope with <paramref name="requestData"/> pre-injected.
    /// Always use this (not CreateAsyncScope) inside background Task.Run blocks.
    /// </summary>
    public static AsyncServiceScope CreateBackgroundScope(
        this IServiceScopeFactory factory,
        ConnectorRequestData requestData)
    {
        var scope = factory.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<RequestDataHolder>().Data = requestData;
        return scope;
    }
}
