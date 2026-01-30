ARG PYTHON_VERSION=3.12
FROM --platform=${TARGETPLATFORM:-linux/amd64} python:${PYTHON_VERSION}-alpine AS build

COPY --from=ghcr.io/openfaas/of-watchdog:0.10.7 /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

ARG UPGRADE_PACKAGES
ARG ADDITIONAL_PACKAGE
ARG DEBUG_MODE="false"

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

# configure WSGI server and healthcheck
USER app

ENV fprocess="python index.py"
ENV cgi_headers="true"
ENV mode="http"
ENV upstream_url="http://127.0.0.1:5000"

HEALTHCHECK --interval=5s CMD [ -e /tmp/.lock ] || exit 1

CMD ["fwatchdog"]
