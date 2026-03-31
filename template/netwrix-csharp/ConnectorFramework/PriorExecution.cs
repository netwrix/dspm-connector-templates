namespace Netwrix.ConnectorFramework;

/// <summary>
/// Represents a prior scan execution returned from the app-data-query service.
/// </summary>
public sealed record PriorExecution(string Id, string Status, int CompletedObjects);
