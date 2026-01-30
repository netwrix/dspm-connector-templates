ARG PYTHON_VERSION=3.12
FROM --platform=${TARGETPLATFORM:-linux/amd64} python:${PYTHON_VERSION}-alpine AS build

ARG UPGRADE_PACKAGES
ARG ADDITIONAL_PACKAGE
ARG DEBUG_MODE="false"
ARG SERVICE_NAME

RUN --mount=type=cache,target=/var/cache/apk \
    if [ "${UPGRADE_PACKAGES}" = "true" ] || [ "${UPGRADE_PACKAGES}" = "1" ]; then apk upgrade; fi && \
    apk add ${ADDITIONAL_PACKAGE}

# Add non root user
RUN addgroup -S app && adduser app -S -G app
RUN chown app /home/app

# Create /app/run entrypoint for connector-api job mode
# This allows the connector-api to invoke the handler directly without Flask
RUN mkdir -p /app && \
    printf '#!/bin/sh\nexec python /home/app/index.py\n' > /app/run && \
    chmod +x /app/run

USER app

ENV PATH=/opt/venv/bin:$PATH:/home/app/.local/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_FROZEN=true \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/var/cache/uv \
    DEBUG_MODE=${DEBUG_MODE} \
    DEBUG_PORT=5678 \
    DEBUG_HOST="0.0.0.0" \
    PYDEVD_DISABLE_FILE_VALIDATION=1

# Template specific steps
WORKDIR /home/app/
COPY --chown=app:app index.py           .
COPY --chown=app:app pyproject.toml     .
COPY --chown=app:app uv.lock            .
USER root
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/var/cache/uv/ \
    uv export --no-dev --format requirements-txt -o requirements.txt && \
    touch requirements-dev.txt; \
    if [ "$DEBUG_MODE" = "true" ]; then \
      uv export --only-dev --format requirements-txt -o requirements-dev.txt; \
    fi

# Build the function directory and install any user-specified components
USER app

RUN mkdir -p function
RUN touch ./function/__init__.py
WORKDIR /home/app/function/
COPY --chown=app:app function/requirements.txt  .

# install function code
USER root
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/var/cache/uv/ \
    uv pip install --system -r ../requirements.txt -r ../requirements-dev.txt -r requirements.txt

COPY --chown=app:app function/   .

FROM build AS ship
WORKDIR /home/app/

# Configure server and healthcheck
USER app

ENV SERVICE_NAME="${SERVICE_NAME}" \
    PORT=8080

# Port for the HTTP server (Flask/Waitress)
EXPOSE 8080

# Health check using wget to the /health endpoint (uses PORT env var)
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

# Run the Python application directly (Flask/Waitress server)
CMD ["python", "index.py"]
