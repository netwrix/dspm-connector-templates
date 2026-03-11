using System.Text.Json;
using System.Threading.Channels;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Buffers objects in memory and flushes to the data-ingestion service when the buffer exceeds 500 KB.
/// Flushing is async and non-blocking: AddObject is synchronous (no I/O).
/// Call FlushAsync to drain remaining objects at the end of a scan.
/// </summary>
public sealed class BatchManager : IAsyncDisposable
{
    private const int ThresholdBytes = 500_000;

    private readonly string _tableName;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConnectorRequestData _requestData;
    private readonly ILogger<BatchManager> _logger;
    private readonly Func<int, CancellationToken, Task>? _onFlushed;

    private readonly Channel<(byte[] Data, int Count)> _flushChannel;
    private readonly Task _flushWorker;

    // Single-writer guarantee: AddObject is called from the connector's scan loop, never concurrently per table.
    private volatile int _writingFlag; // 0 = free, 1 = in use — enforces the single-writer contract at runtime
    private MemoryStream _buffer;
    private int _pendingObjectCount;

    public BatchManager(
        string tableName,
        IHttpClientFactory httpClientFactory,
        ConnectorRequestData requestData,
        ILogger<BatchManager> logger,
        Func<int, CancellationToken, Task>? onFlushed = null)
    {
        _tableName = tableName;
        _httpClientFactory = httpClientFactory;
        _requestData = requestData;
        _logger = logger;
        _onFlushed = onFlushed;

        _buffer = NewBuffer();

        _flushChannel = Channel.CreateUnbounded<(byte[], int)>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
        });

        _flushWorker = Task.Run(RunFlushWorkerAsync);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds an object to the buffer. If the buffer exceeds 500 KB, an async flush is triggered.
    /// This method is synchronous — it never performs I/O.
    /// </summary>
    /// <param name="obj">The object to add.</param>
    /// <param name="updateStatus">When true (default), counts this object for completion reporting.</param>
    public void AddObject(object obj, bool updateStatus = true)
    {
        if (obj is null)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _writingFlag, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                $"Concurrent AddObject calls detected for table '{_tableName}'. Only a single writer is supported per BatchManager.");
        }

        try
        {
            var enhancedBytes = BuildEnhancedObject(obj);

            if (_buffer.Length + enhancedBytes.Length > ThresholdBytes && _buffer.Length > 1)
            {
                var snapshot = FinaliseBuffer();
                if (!_flushChannel.Writer.TryWrite(snapshot))
                {
                    _logger.LogError("Failed to enqueue batch for table {Table} — channel is closed", _tableName);
                }

                _buffer = NewBuffer();
                _pendingObjectCount = 0;
            }

            _buffer.Write(enhancedBytes);
            _buffer.WriteByte((byte)',');
            if (updateStatus)
            {
                _pendingObjectCount++;
            }
        }
        finally
        {
            _writingFlag = 0;
        }
    }

    /// <summary>
    /// Flushes remaining buffered objects and waits for the background worker to drain.
    /// Call this once at the end of a scan before the handler returns.
    /// </summary>
    public async Task FlushAsync(CancellationToken ct = default)
    {
        if (_buffer.Length > 1)
        {
            var snapshot = FinaliseBuffer();
            if (!_flushChannel.Writer.TryWrite(snapshot))
            {
                _logger.LogError("Failed to enqueue final batch for table {Table} — channel is closed", _tableName);
            }

            _buffer = NewBuffer();
            _pendingObjectCount = 0;
        }

        _flushChannel.Writer.TryComplete();
        await _flushWorker;
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private static MemoryStream NewBuffer()
    {
        var ms = new MemoryStream();
        ms.WriteByte((byte)'[');
        return ms;
    }

    private (byte[] Data, int Count) FinaliseBuffer()
    {
        // _buffer.ToArray() returns a new copy — safe to mutate the trailing comma to ']'
        var result = _buffer.ToArray();
        result[^1] = (byte)']';
        return (result, _pendingObjectCount);
    }

    private byte[] BuildEnhancedObject(object obj)
    {
        using var ms = new MemoryStream();
        using var writer = new Utf8JsonWriter(ms);

        writer.WriteStartObject();
        writer.WriteString("scan_id", _requestData.ScanId ?? "");
        writer.WriteString("scan_execution_id", _requestData.ScanExecutionId ?? "");
        writer.WriteString("scanned_at", DateTimeOffset.UtcNow.ToString("O"));

        // Copy the connector object's properties after the injected framework fields
        using var doc = JsonSerializer.SerializeToDocument(obj);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            prop.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();
        return ms.ToArray();
    }

    private async Task RunFlushWorkerAsync()
    {
        await foreach (var (payload, count) in _flushChannel.Reader.ReadAllAsync())
        {
            await PostBatchAsync(payload, count);
        }
    }

    private async Task PostBatchAsync(byte[] dataArray, int count)
    {
        var sourceType = Environment.GetEnvironmentVariable("SOURCE_TYPE") ?? "";

        // Build envelope using Utf8JsonWriter to avoid JSON injection via sourceType / tableName
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WriteString("sourceType", sourceType);
            writer.WriteString("table", _tableName);
            writer.WritePropertyName("data");
            writer.WriteRawValue(dataArray); // dataArray is a valid JSON array
            writer.WriteEndObject();
        }
        var envelope = ms.ToArray();

        var serviceUrl = ServiceUrlHelper.Resolve("SAVE_DATA_FUNCTION", "data-ingestion", useAsync: true);

        try
        {
            using var client = _httpClientFactory.CreateClient("data-ingestion");
            using var content = new ByteArrayContent(envelope);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl);
            request.Content = content;
            foreach (var (k, v) in GetCallerHeaders())
            {
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                if (_onFlushed is not null && count > 0)
                {
                    await _onFlushed(count, CancellationToken.None);
                }
            }
            else
            {
                _logger.LogWarning("Batch flush returned {StatusCode} for table {Table}", (int)response.StatusCode, _tableName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Batch flush failed for table {Table}", _tableName);
        }
    }

    private IEnumerable<KeyValuePair<string, string>> GetCallerHeaders()
    {
        if (_requestData.ScanId is not null)
        {
            yield return new("Scan-Id", _requestData.ScanId);
        }

        if (_requestData.ScanExecutionId is not null)
        {
            yield return new("Scan-Execution-Id", _requestData.ScanExecutionId);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _flushChannel.Writer.TryComplete();
        await _flushWorker;
    }
}
