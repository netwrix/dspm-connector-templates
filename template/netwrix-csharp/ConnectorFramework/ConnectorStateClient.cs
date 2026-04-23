using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;

namespace Netwrix.ConnectorFramework;

/// <summary>
/// Typed HTTP client for the connector-state service. Owns all transport concerns:
/// base URL (set via DI registration), constant default headers (Function-Type),
/// per-request headers (Scan-Id, Scan-Execution-Id, traceparent), error wrapping,
/// and correct cancellation propagation.
/// </summary>
public sealed class ConnectorStateClient
{
    /// <summary>Named client key used in both DI registration and singleton factory creation.</summary>
    public const string HttpClientName = "connector-state";

    // Maximum query-string length for a single DELETE request. Each key becomes a &name=
    // query parameter; splitting into batches prevents UriFormatException (.NET URI limit
    // is ~65,519 chars) and respects typical proxy/nginx URL size limits (~8 KB).
    internal const int MaxDeleteQueryLength = 4_000;

    private readonly HttpClient _client;
    private readonly ILogger<ConnectorStateClient> _logger;

    public ConnectorStateClient(HttpClient client, ILogger<ConnectorStateClient> logger)
    {
        _client = client;
        _logger = logger;
    }

    // ── Public methods ───────────────────────────────────────────────────────

    public async Task<Dictionary<string, string>> GetStateAsync(
        string scanId, string? scanExecutionId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"?scanId={Uri.EscapeDataString(scanId)}");
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state GET returned {(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var error = root.TryGetProperty("error", out var errProp)
                    ? errProp.GetString() : "Unknown error";
                throw new StateStorageException($"connector-state GET failed: {error}");
            }

            if (root.TryGetProperty("data", out var dataProp))
            {
                return dataProp.Deserialize<Dictionary<string, string>>()
                       ?? new Dictionary<string, string>();
            }

            return new Dictionary<string, string>();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state GET failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state GET failed for scan {scanId}", ex);
        }
    }

    public async Task<string?> GetStateValueAsync(
        string scanId, string? scanExecutionId, string key, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"?scanId={Uri.EscapeDataString(scanId)}");
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state GET returned {(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
            {
                var error = root.TryGetProperty("error", out var errProp)
                    ? errProp.GetString() : "Unknown error";
                throw new StateStorageException($"connector-state GET failed: {error}");
            }

            if (root.TryGetProperty("data", out var dataProp) &&
                dataProp.TryGetProperty(key, out var valueProp))
            {
                return valueProp.GetString();
            }

            return null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state GET failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state GET failed for scan {scanId}", ex);
        }
    }

    public async Task PostStateAsync(
        string scanId, string? scanExecutionId, Dictionary<string, string> data, CancellationToken ct)
    {
        var payload = new { scanId, data };
        using var request = new HttpRequestMessage(HttpMethod.Post, "/")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
        };
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state POST returned {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("success", out var successProp) && !successProp.GetBoolean())
                {
                    var error = root.TryGetProperty("error", out var errProp)
                        ? errProp.GetString() : "Unknown error";
                    throw new StateStorageException($"connector-state POST failed: {error}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state POST failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state POST failed for scan {scanId}", ex);
        }
    }

    /// <summary>
    /// Deletes all <paramref name="names"/> from the connector-state service, automatically
    /// splitting into URL-length-bounded batches to avoid <see cref="UriFormatException"/>
    /// when key count or key length would produce a query string exceeding
    /// <see cref="MaxDeleteQueryLength"/> characters.
    /// </summary>
    public async Task DeleteManyAsync(
        string scanId, string? scanExecutionId, string[] names, CancellationToken ct)
    {
        var baseQs = $"?scanId={Uri.EscapeDataString(scanId)}";
        var sb = new StringBuilder();

        var i = 0;
        while (i < names.Length)
        {
            sb.Clear();
            sb.Append(baseQs);
            var batchStart = i;

            while (i < names.Length)
            {
                var escaped = $"&name={Uri.EscapeDataString(names[i])}";
                // If adding this key would exceed the limit AND we already have at least one key
                // in the batch, flush now. A single key that is longer than the limit is sent
                // alone (can't split further).
                if (sb.Length + escaped.Length > MaxDeleteQueryLength && i > batchStart)
                {
                    break;
                }

                sb.Append(escaped);
                i++;
            }

            _logger.LogDebug(
                "Deleting state keys {Start}–{End} of {Total} for scan {ScanId}",
                batchStart, i - 1, names.Length, scanId);

            await SendDeleteAsync(scanId, scanExecutionId, sb.ToString(), ct);
        }
    }

    // ── Private HTTP helpers ─────────────────────────────────────────────────

    private async Task SendDeleteAsync(
        string scanId, string? scanExecutionId, string queryString, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, queryString);
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state DELETE returned {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                if (root.TryGetProperty("success", out var successProp) && !successProp.GetBoolean())
                {
                    var error = root.TryGetProperty("error", out var errProp)
                        ? errProp.GetString() : "Unknown error";
                    throw new StateStorageException($"connector-state DELETE failed: {error}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state DELETE failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state DELETE failed for scan {scanId}", ex);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void AddPerRequestHeaders(
        HttpRequestMessage request, string scanId, string? scanExecutionId)
    {
        request.Headers.TryAddWithoutValidation("Scan-Id", scanId);
        if (scanExecutionId is not null)
        {
            request.Headers.TryAddWithoutValidation("Scan-Execution-Id", scanExecutionId);
        }

        // Function-Type is a default header set at DI registration time — not added here.

        var activity = Activity.Current;
        if (activity?.Id is not null)
        {
            request.Headers.TryAddWithoutValidation("traceparent", activity.Id);
        }

        if (!string.IsNullOrEmpty(activity?.TraceStateString))
        {
            request.Headers.TryAddWithoutValidation("tracestate", activity.TraceStateString);
        }
    }
}
