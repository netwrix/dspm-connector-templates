using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace function;

public static class Handler
{
    // MapEndpoints is used to register WebApplication
    // HTTP handlers for various paths and HTTP methods.
    public static void MapEndpoints(WebApplication app)
    {
        app.MapGet("/", () =>
        {
            return "Hello from OpenFaaS.";
        });
    }

    // MapServices can be used to configure additional
    // WebApplication services
    public static void MapServices(IServiceCollection services)
    {
    }
}