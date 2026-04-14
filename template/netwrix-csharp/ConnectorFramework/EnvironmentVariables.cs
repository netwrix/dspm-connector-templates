namespace Netwrix.ConnectorFramework;

/// <summary>
/// Environment variable names read by the ConnectorFramework host.
/// </summary>
internal static class EnvironmentVariables
{
    // Execution control
    internal const string ExecutionMode = "EXECUTION_MODE";
    internal const string RequestData = "REQUEST_DATA";
    internal const string RequestPath = "REQUEST_PATH";

    // Networking
    internal const string Port = "PORT";

    // Redis
    internal const string RedisUrl = "REDIS_URL";

    // Scan context
    internal const string ScanId = "SCAN_ID";
    internal const string ScanExecutionId = "SCAN_EXECUTION_ID";
    internal const string SourceId = "SOURCE_ID";
    internal const string SourceType = "SOURCE_TYPE";
    internal const string SourceVersion = "SOURCE_VERSION";
    internal const string FunctionType = "FUNCTION_TYPE";

    // Security
    internal const string SecretMappings = "SECRET_MAPPINGS";

    // Observability
    internal const string OtelEnabled = "OTEL_ENABLED";
    internal const string OtelExporterOtlpEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT";
    internal const string Environment = "ENVIRONMENT";
    internal const string LogLevel = "LOG_LEVEL";

    // Service URL env-var overrides (passed to ServiceUrlHelper.Resolve as the first argument)
    internal const string SaveDataFunction = "SAVE_DATA_FUNCTION";
    internal const string AppUpdateExecutionFunction = "APP_UPDATE_EXECUTION_FUNCTION";
    internal const string AppDataQueryFunction = "APP_DATA_QUERY_FUNCTION";

    // Service discovery
    internal const string RunLocal = "RUN_LOCAL";
    internal const string UseOpenfaasGateway = "USE_OPENFAAS_GATEWAY";
    internal const string OpenfaasGateway = "OPENFAAS_GATEWAY";
    internal const string CommonFunctionsNamespace = "COMMON_FUNCTIONS_NAMESPACE";
}

/// <summary>
/// Named downstream service identifiers used for service URL resolution and named HttpClient creation.
/// </summary>
internal static class ServiceNames
{
    internal const string DataIngestion = "data-ingestion";
    internal const string AppUpdateExecution = "app-update-execution";
    internal const string UpdateExecution = "update-execution";
    internal const string AppDataQuery = "app-data-query";
}
