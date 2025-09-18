ARG PYTHON_VERSION=3.12
FROM --platform=${TARGETPLATFORM:-linux/amd64} python:${PYTHON_VERSION}-alpine AS build

COPY --from=ghcr.io/openfaas/of-watchdog:0.10.7 /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

ARG UPGRADE_PACKAGES
ARG ADDITIONAL_PACKAGE

RUN --mount=type=cache,target=/var/cache/apk \
    if [ "${UPGRADE_PACKAGES}" = "true" ] || [ "${UPGRADE_PACKAGES}" = "1" ]; then apk upgrade; fi && \
    apk add ${ADDITIONAL_PACKAGE}

# Add non root user
RUN addgroup -S app && adduser app -S -G app
RUN chown app /home/app

USER app

ENV PATH=$PATH:/home/app/.local/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_FROZEN=true \
    UV_NO_EDITABLE=true \
    UV_NO_MANAGED_PYTHON=true \
    UV_COMPILE_BYTECODE=true \
    UV_SYSTEM_PYTHON=true \
    UV_CACHE_DIR=/var/cache/uv \
    UV_PROJECT_ENVIRONMENT=/usr/local/

# Template specific steps
WORKDIR /home/app/
COPY --chown=app:app local_testing.py   .
COPY --chown=app:app index.py           .
COPY --chown=app:app pyproject.toml     .
COPY --chown=app:app uv.lock            .
USER root
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/var/cache/uv/ \
    uv sync


# Build the function directory and install any user-specified components
USER app

RUN mkdir -p function
RUN touch ./function/__init__.py
WORKDIR /home/app/function/
COPY --chown=app:app function/pyproject.toml    .
COPY --chown=app:app function/uv.lock           .

# install function code
USER root
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/var/cache/uv/ \
    uv sync

COPY --chown=app:app function/   .

FROM build AS test
ARG TEST_COMMAND=tox
ARG TEST_ENABLED=true
RUN [ "$TEST_ENABLED" = "false" ] && echo "skipping tests" || eval "$TEST_COMMAND"

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
