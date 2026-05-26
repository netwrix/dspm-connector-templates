using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Netwrix.Overlord.Sdk.Core.Exceptions;
using Netwrix.Overlord.Sdk.Core.Storage.Exceptions;
using Polly.CircuitBreaker;

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

    private readonly HttpClient _client;
    private readonly ILogger<ConnectorStateClient> _logger;

    public ConnectorStateClient(HttpClient client, ILogger<ConnectorStateClient> logger)
    {
        _client = client;
        _logger = logger;
    }

    // ── Public methods ───────────────────────────────────────────────────────

    /// <summary>
    /// Returns all key-value pairs stored for <paramref name="scanId"/>, or an empty dictionary
    /// if none exist.
    /// </summary>
    /// <param name="scanId">The scan whose state to retrieve.</param>
    /// <param name="scanExecutionId">Optional execution ID forwarded as a request header for tracing.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<Dictionary<string, string>> GetStateAsync(
        string scanId, string? scanExecutionId, CancellationToken ct)
    {
        return await FetchStateAsync(scanId, scanExecutionId, ct);
    }

    /// <summary>
    /// Returns all key names stored for <paramref name="scanId"/>, or an empty array if none exist.
    /// </summary>
    /// <param name="scanId">The scan whose state keys to list.</param>
    /// <param name="scanExecutionId">Optional execution ID forwarded as a request header for tracing.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<string[]> ListKeysAsync(
        string scanId, string? scanExecutionId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/{Uri.EscapeDataString(scanId)}/keys");
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return [];

            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state GET keys returned {(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            return await JsonSerializer.DeserializeAsync<string[]>(stream, cancellationToken: ct)
                ?? [];
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (BrokenCircuitException ex)
        {
            throw new InfrastructureUnavailableException("connector-state", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state GET keys failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state GET keys failed for scan {scanId}", ex);
        }
    }

    /// <summary>
    /// Returns the serialized value for <paramref name="key"/> within <paramref name="scanId"/>'s
    /// state, or <c>null</c> if the key does not exist.
    /// </summary>
    /// <param name="scanId">The scan whose state to query.</param>
    /// <param name="scanExecutionId">Optional execution ID forwarded as a request header for tracing.</param>
    /// <param name="key">The state key to look up.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<string?> GetStateValueAsync(
        string scanId, string? scanExecutionId, string key, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/{Uri.EscapeDataString(scanId)}/keys/{Uri.EscapeDataString(key)}");
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return null;

            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state GET key returned {(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var dict = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(stream, cancellationToken: ct);
            return dict?.TryGetValue(key, out var value) == true ? value : null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (BrokenCircuitException ex)
        {
            throw new InfrastructureUnavailableException("connector-state", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state GET key failed for scan {ScanId}, key {Key}", scanId, key);
            throw new StateStorageException($"connector-state GET key failed for scan {scanId}", ex);
        }
    }

    private async Task<Dictionary<string, string>> FetchStateAsync(
        string scanId, string? scanExecutionId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/{Uri.EscapeDataString(scanId)}");
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new Dictionary<string, string>();

            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state GET returned {(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            return await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(stream, cancellationToken: ct)
                ?? new Dictionary<string, string>();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StateStorageException)
        {
            throw;
        }
        catch (BrokenCircuitException ex)
        {
            throw new InfrastructureUnavailableException("connector-state", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state GET failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state GET failed for scan {scanId}", ex);
        }
    }

    /// <summary>
    /// Writes (upserts) the key-value pairs in <paramref name="data"/> into the connector-state
    /// service for <paramref name="scanId"/>.
    /// </summary>
    /// <param name="scanId">The scan whose state to update.</param>
    /// <param name="scanExecutionId">Optional execution ID forwarded as a request header for tracing.</param>
    /// <param name="data">Key-value pairs to upsert.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task PutStateAsync(
        string scanId, string? scanExecutionId, Dictionary<string, string> data, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/{Uri.EscapeDataString(scanId)}")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(data), Encoding.UTF8, "application/json"),
        };
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new StateStorageException(
                    $"connector-state PUT returned {(int)response.StatusCode}");
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
        catch (BrokenCircuitException ex)
        {
            throw new InfrastructureUnavailableException("connector-state", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "connector-state PUT failed for scan {ScanId}", scanId);
            throw new StateStorageException($"connector-state PUT failed for scan {scanId}", ex);
        }
    }

    /// <summary>
    /// Deletes all <paramref name="names"/> from the connector-state service for
    /// <paramref name="scanId"/>.
    /// </summary>
    /// <param name="scanId">The scan whose state keys should be deleted.</param>
    /// <param name="scanExecutionId">Optional execution ID forwarded as a request header for tracing.</param>
    /// <param name="names">State key names to delete.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task DeleteManyAsync(
        string scanId, string? scanExecutionId, string[] names, CancellationToken ct)
    {
        if (names.Length == 0)
            return;

        using var request = new HttpRequestMessage(
            HttpMethod.Delete, $"/{Uri.EscapeDataString(scanId)}/keys")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(names), Encoding.UTF8, "application/json"),
        };
        AddPerRequestHeaders(request, scanId, scanExecutionId);

        try
        {
            using var response = await _client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode &&
                response.StatusCode != System.Net.HttpStatusCode.NotFound)
            {
                throw new StateStorageException(
                    $"connector-state DELETE returned {(int)response.StatusCode}");
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
        catch (BrokenCircuitException ex)
        {
            throw new InfrastructureUnavailableException("connector-state", ex);
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
