ARG FUNCTION_DIR
ARG NUGET_TOKEN

FROM --platform=${TARGETPLATFORM:-linux/amd64} mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build

# Re-declare ARGs inside the stage — ARGs defined before FROM are only visible in FROM lines.
ARG FUNCTION_DIR
ARG NUGET_TOKEN
ARG UPGRADE_PACKAGES
# Promote to ENV so NuGet.config's %NUGET_TOKEN% substitution can read it at restore time.
ENV NUGET_TOKEN=${NUGET_TOKEN}

RUN if [ "${UPGRADE_PACKAGES}" = "true" ] || [ "${UPGRADE_PACKAGES}" = "1" ]; then apk upgrade; fi

WORKDIR /src

# Layer 1: restore NuGet packages (cached unless .csproj files change)
# NuGet.config points to the private Netwrix feed; NUGET_TOKEN supplies the credentials.
COPY ./template/netwrix-csharp/NuGet.config ./
COPY ./template/netwrix-csharp/ConnectorFramework/ConnectorFramework.csproj ConnectorFramework/
COPY ${FUNCTION_DIR}/Function.csproj function/
RUN dotnet restore ConnectorFramework/ConnectorFramework.csproj --configfile NuGet.config && \
    dotnet restore function/Function.csproj --configfile NuGet.config

# Layer 2: build and publish framework
COPY ./template/netwrix-csharp/ConnectorFramework/ ConnectorFramework/
RUN dotnet publish ConnectorFramework/ConnectorFramework.csproj \
    --configuration Release \
    --no-restore \
    --output /app

# Layer 3: build and publish connector function
# Copy only the baseline project file from the template — NOT Handler.cs.
# Connectors provide their own handler; copying the template stub would create a second
# IConnectorHandler implementation and cause a discovery error at startup.
COPY ./template/netwrix-csharp/function/Function.csproj function/
# Overlay with all connector-specific files (overrides Function.csproj if present)
COPY ${FUNCTION_DIR}/ function/
RUN dotnet publish function/Function.csproj \
    --configuration Release \
    --no-restore \
    --output /app

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM --platform=${TARGETPLATFORM:-linux/amd64} mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS ship

# Newer aspnet:8.0-alpine images ship with 'app' group/user pre-created; skip if already present.
RUN addgroup -S app 2>/dev/null || true && adduser app -S -G app 2>/dev/null || true
RUN chown app /home/app
RUN apk add --no-cache curl

# Create /app/run entrypoint for connector-api job mode
RUN mkdir -p /app && \
    printf '#!/bin/sh\nexec dotnet /app/ConnectorFramework.dll\n' > /app/run && \
    chmod +x /app/run

USER app
WORKDIR /app
COPY --from=build --chown=app:app /app .

ENV ASPNETCORE_URLS=""
ENV PORT=5000

EXPOSE 5000

HEALTHCHECK --interval=5s --timeout=3s \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["dotnet", "ConnectorFramework.dll"]
