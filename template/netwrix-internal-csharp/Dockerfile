# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build

# Install CA certificates and curl for better SSL handling
RUN apk add --no-cache ca-certificates curl

WORKDIR /src

# Copy local packages and config
COPY function/packages/ ./packages/
COPY NuGet.config .

# Copy project files
COPY Root.csproj .
COPY function/Function.csproj function/

# Clear NuGet cache and configure sources with timeouts
RUN dotnet nuget locals all --clear
RUN dotnet nuget remove source local || true
RUN dotnet nuget add source ./packages --name local
RUN dotnet nuget list source

# Restore with timeouts and offline-first approach
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV NUGET_XMLDOC_MODE=skip
RUN timeout 300 dotnet restore --verbosity normal --configfile NuGet.config

# Copy Program.cs from template (contains the entry point)
COPY Program.cs .

# Copy template source files to function directory (shared classes)
COPY FunctionContext.cs FunctionRequest.cs FunctionResponse.cs ./function/

# Copy all source files from function directory
COPY function/*.cs ./function/
RUN dotnet publish -c Release -o /app/publish --no-self-contained --framework net8.0

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime

# Use existing app user or create one
RUN id app >/dev/null 2>&1 || adduser -S app
WORKDIR /app
COPY --from=build /app/publish .

# Set up OpenFaaS watchdog
COPY --from=ghcr.io/openfaas/of-watchdog:0.10.7 /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

# Configure environment
ENV fprocess="dotnet Root.dll"
ENV cgi_headers="true"
ENV mode="http"
ENV upstream_url="http://127.0.0.1:3000"

USER app

EXPOSE 8080
HEALTHCHECK --interval=5s CMD [ -e /tmp/.lock ] || exit 1

CMD ["fwatchdog"]