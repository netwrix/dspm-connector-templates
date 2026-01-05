using Microsoft.AspNetCore.Http;
using System.Text;

namespace function;

public class FunctionRequest
{
    private readonly HttpContext _httpContext;
    private string? _bodyCache;

    public FunctionRequest(HttpContext httpContext)
    {
        _httpContext = httpContext;
    }

    public string Method => _httpContext.Request.Method;
    public string Path => _httpContext.Request.Path;
    public IHeaderDictionary Headers => _httpContext.Request.Headers;
    public IQueryCollection Query => _httpContext.Request.Query;

    public async Task<string> GetBodyAsync()
    {
        if (_bodyCache != null)
            return _bodyCache;

        using var reader = new StreamReader(_httpContext.Request.Body, Encoding.UTF8);
        _bodyCache = await reader.ReadToEndAsync();
        return _bodyCache;
    }
}