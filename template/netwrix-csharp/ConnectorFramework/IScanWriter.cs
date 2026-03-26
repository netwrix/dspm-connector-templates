namespace Netwrix.ConnectorFramework;

/// <summary>
/// Abstraction over the write side of <see cref="FunctionContext"/>.
/// Implemented by <see cref="FunctionContext"/>; inject this interface into facades
/// that only need to buffer and flush scanned objects.
/// </summary>
public interface IScanWriter
{
    void SaveObject(string tableName, object obj, bool updateStatus = true);
    Task FlushTablesAsync(CancellationToken ct = default);
}
