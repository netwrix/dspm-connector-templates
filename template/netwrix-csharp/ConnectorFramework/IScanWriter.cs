namespace Netwrix.ConnectorFramework;

/// <summary>
/// Abstraction over the write side of <see cref="FunctionContext"/>.
/// Implemented by <see cref="FunctionContext"/>; inject this interface into facades
/// that only need to buffer and flush scanned objects.
/// </summary>
public interface IScanWriter
{
    void SaveObject(string tableName, object obj, bool updateStatus = true);

    /// <summary>
    /// Drains in-memory buffers for all tables to the flush channel without closing channels.
    /// Safe to call from concurrent workers — does not complete BatchManagers.
    /// </summary>
    void FlushBuffers(CancellationToken ct = default);

    Task FlushTablesAsync(CancellationToken ct = default);
}
