namespace Netwrix.ConnectorFramework;

/// <summary>
/// Decouples FunctionContext from HttpContext so it works in both HTTP and job modes.
/// In HTTP mode this is populated from the incoming request by a scoped DI factory.
/// In job mode this is constructed from environment variables by Program.cs.
///
/// Intentionally a class rather than a record: record equality on byte[] compares by reference,
/// not content, which makes structural equality misleading.
/// </summary>
public sealed class ConnectorRequestData
{
    public string Method { get; }
    public string Path { get; }
    public IReadOnlyDictionary<string, string> Headers { get; }
    public byte[]? Body { get; }
    public ExecutionContext Execution { get; }

    public ConnectorRequestData(
        string Method,
        string Path,
        IReadOnlyDictionary<string, string> Headers,
        byte[]? Body,
        ExecutionContext Execution)
    {
        this.Method = Method;
        this.Path = Path;
        this.Headers = Headers;
        this.Body = Body;
        this.Execution = Execution;
    }
}
