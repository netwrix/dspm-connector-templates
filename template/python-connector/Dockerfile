ARG PYTHON_VERSION=3.12
FROM --platform=${TARGETPLATFORM:-linux/amd64} python:${PYTHON_VERSION}-alpine AS build

COPY --from=ghcr.io/openfaas/of-watchdog:0.10.7 /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

ARG UPGRADE_PACKAGES
ARG ADDITIONAL_PACKAGE
ARG TEMPLATE_DIR="."
ARG RUN_LOCAL="false"
ARG DEBUG_PORT=5678
ARG DEBUG_HOST="0.0.0.0"

RUN --mount=type=cache,target=/var/cache/apk \
    if [ "${UPGRADE_PACKAGES}" = "true" ] || [ "${UPGRADE_PACKAGES}" = "1" ]; then apk upgrade; fi && \
    apk add ${ADDITIONAL_PACKAGE} && \
    if [ "${RUN_LOCAL}" = "true" ]; then \
        apk add git lazygit fzf curl neovim ripgrep alpine-sdk && \
        su - app -c 'git clone https://github.com/LazyVim/starter ~/.config/nvim' && \
        su - app -c 'rm -rf ~/.config/nvim/.git' && \
        su - app -c 'echo "alias vim=nvim" >> ~/.bashrc'; \
    fi

# Add non root user
RUN addgroup -S app && adduser app -S -G app
RUN chown app /home/app

USER app

ENV PATH=/opt/venv/bin:$PATH:/home/app/.local/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_FROZEN=true \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/var/cache/uv \
    DEBUG_MODE=${DEBUG_MODE} \
    RUN_LOCAL=${RUN_LOCAL} \
    DEBUG_PORT=${DEBUG_PORT} \
    DEBUG_HOST=${DEBUG_HOST} \
    PYDEVD_DISABLE_FILE_VALIDATION=1

# Template specific steps
WORKDIR /home/app/
COPY --chown=app:app ${TEMPLATE_DIR}/connector-python/index.py           .
COPY --chown=app:app ${TEMPLATE_DIR}/connector-python/pyproject.toml     .
COPY --chown=app:app ${TEMPLATE_DIR}/connector-python/uv.lock            .
USER root
RUN --mount=from=ghcr.io/astral-sh/uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/var/cache/uv/ \
    uv export --no-dev --format requirements-txt -o requirements.txt && \
    touch requirements-dev.txt; \
    if [ "$RUN_LOCAL" = "true" ]; then \
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
