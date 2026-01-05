using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.Text.Json;

namespace function;

public static class Handler
{
    // MapEndpoints is used to register WebApplication
    // HTTP handlers for various paths and HTTP methods.
    public static void MapEndpoints(WebApplication app, ActivitySource activitySource)
    {
        app.MapGet("/health", () => Results.Json(new { status = "ok" }));

        // Main handler endpoint - catch all routes
        app.Map("/{**path}", async (HttpContext httpContext, FunctionContext context) =>
        {
            using var processRequestActivity = activitySource.StartActivity("process_request");
            var request = new FunctionRequest(httpContext);

            try
            {
                context.Log("Received request", new
                {
                    http_method = request.Method,
                    http_path = request.Path
                });

                // Load secrets from environment
                context.LoadSecrets();

                // Call your custom handler logic here
                var response = await HandleAsync(request, context);

                processRequestActivity?.SetTag("http.status_code", response.StatusCode);
                processRequestActivity?.SetStatus(ActivityStatusCode.Ok);
                context.Log("Request completed", new { http_status_code = response.StatusCode });

                // Format response
                httpContext.Response.StatusCode = response.StatusCode;
                httpContext.Response.ContentType = "application/json";

                var responseJson = JsonSerializer.Serialize(response.Body);
                await httpContext.Response.WriteAsync(responseJson);
            }
            catch (Exception ex)
            {
                processRequestActivity?.SetTag("http.status_code", 500);
                processRequestActivity?.SetStatus(ActivityStatusCode.Error, ex.Message);

                context.LogError($"Request failed: {ex.Message}", new { error_type = ex.GetType().Name, error_message = ex.Message });
                httpContext.Response.StatusCode = 500;
                httpContext.Response.ContentType = "application/json";
                await httpContext.Response.WriteAsync(JsonSerializer.Serialize(new { error = ex.Message }));
            }
        });
    }

    // MapServices can be used to configure additional
    // WebApplication services
    public static void MapServices(IServiceCollection services)
    {
        // Add any custom services needed by your function here
    }

    // This is the main handler method that function developers should implement
    // Replace this with your actual function logic
    private static async Task<FunctionResponse> HandleAsync(FunctionRequest request, FunctionContext context)
    {
        // Example implementation - replace with your actual function logic
        var body = await request.GetBodyAsync();
        
        context.Log("Processing request", new { body_length = body.Length });

        // Your function logic goes here
        // You can use context.Log(), context.LogError(), context.LogWarning(), etc.
        // All logs will be automatically sent to OpenTelemetry

        return new FunctionResponse
        {
            StatusCode = 200,
            Body = new { message = "Hello from OpenFaaS with OTEL logging!" }
        };
    }
}