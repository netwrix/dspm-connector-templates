ARG FUNCTION_DIR
ARG NUGET_TOKEN
ARG IMAGE_VERSION=dev

FROM --platform=${TARGETPLATFORM:-linux/amd64} mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build

# Re-declare ARGs inside the stage — ARGs defined before FROM are only visible in FROM lines.
ARG FUNCTION_DIR
ARG NUGET_TOKEN
ARG UPGRADE_PACKAGES
ARG IMAGE_VERSION=dev
# Promote to ENV so NuGet.config's %NUGET_TOKEN% substitution can read it at restore time.
ENV NUGET_TOKEN=${NUGET_TOKEN}

RUN if [ "${UPGRADE_PACKAGES}" = "true" ] || [ "${UPGRADE_PACKAGES}" = "1" ]; then apk upgrade; fi

WORKDIR /src

# Layer 1: restore NuGet packages (cached unless .csproj files change)
# NuGet.config points to the private Netwrix feed; NUGET_TOKEN supplies the credentials.
# ConnectorFramework is copied to the same relative path as the local checkout so that
# the connector's named .csproj (../template/netwrix-csharp/ConnectorFramework/...) resolves
# identically in both Docker and local development — eliminating the need for a separate
# Docker-only Function.csproj per handler.
COPY ./template/netwrix-csharp/NuGet.config ./
COPY ./template/netwrix-csharp/ConnectorFramework/ConnectorFramework.csproj template/netwrix-csharp/ConnectorFramework/
COPY ${FUNCTION_DIR}/*.csproj function/
RUN dotnet restore template/netwrix-csharp/ConnectorFramework/ConnectorFramework.csproj --configfile NuGet.config && \
    dotnet restore function/ --configfile NuGet.config

# Layer 2: build and publish framework
COPY ./template/netwrix-csharp/ConnectorFramework/ template/netwrix-csharp/ConnectorFramework/
RUN dotnet publish template/netwrix-csharp/ConnectorFramework/ConnectorFramework.csproj \
    --configuration Release \
    --no-restore \
    --output /app

# Layer 3: build and publish connector function
COPY ${FUNCTION_DIR}/ function/
RUN dotnet publish function/ \
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

ARG IMAGE_VERSION=dev
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV ASPNETCORE_URLS=""
ENV PORT=5000

EXPOSE 5000

HEALTHCHECK --interval=5s --timeout=3s \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["dotnet", "ConnectorFramework.dll"]
