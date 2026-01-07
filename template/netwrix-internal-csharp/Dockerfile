FROM ghcr.io/openfaas/of-watchdog:0.10.1 AS watchdog

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

WORKDIR /src
COPY NuGet.config .
COPY function/packages/ ./packages/
COPY Root.csproj .
COPY function/Function.csproj function/
RUN dotnet nuget remove source local 2>/dev/null || true && dotnet nuget add source /src/packages --name local
RUN dotnet restore Root.csproj --configfile NuGet.config
COPY Program.cs .
COPY FunctionContext.cs FunctionRequest.cs FunctionResponse.cs ./function/
COPY function/*.cs ./function/
RUN dotnet publish -c release -o /app

RUN mkdir -p function/static

FROM mcr.microsoft.com/dotnet/aspnet:8.0
COPY --from=watchdog /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

WORKDIR /app
COPY --from=build /app .
COPY --from=build src/function/static static

USER app

ENV fprocess="dotnet Root.dll"
ENV upstream_url="http://127.0.0.1:3000"
ENV mode="http"

ENTRYPOINT ["fwatchdog"]