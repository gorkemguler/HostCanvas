# syntax=docker/dockerfile:1.7
FROM node:24.21.0-bookworm-slim AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24.21.0-bookworm-slim AS runtime

ARG TESTSSL_VERSION=3.2.4
ARG TESTSSL_SHA256=98528f8a0ac07f1e226efaa8ead438247df8efcb8fee4e056a937ab82a305490

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    bsdextrautils \
    ca-certificates \
    curl \
    dnsutils \
    openssl \
    procps \
  && curl -fsSL "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" -o /tmp/testssl.tar.gz \
  && echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - \
  && mkdir -p /opt/testssl \
  && tar -xzf /tmp/testssl.tar.gz --strip-components=1 -C /opt/testssl \
  && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
  && rm -f /tmp/testssl.tar.gz \
  && apt-get purge -y --auto-remove curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app /app

RUN groupadd --system --gid 10001 tlsentinel \
  && useradd --system --uid 10001 --gid tlsentinel --home-dir /app tlsentinel \
  && mkdir -p /data /app/.wrangler \
  && chown -R tlsentinel:tlsentinel /data /app/.wrangler

ENV NODE_ENV=production \
    TLS_SENTINEL_DATA_DIR=/data \
    TLS_SENTINEL_API_HOST=0.0.0.0 \
    TLS_SENTINEL_API_PORT=8787 \
    TLS_SENTINEL_WEB_HOST=0.0.0.0 \
    TLS_SENTINEL_WEB_PORT=3000 \
    TLS_SENTINEL_UI_ORIGINS=http://localhost:3000,http://127.0.0.1:3000 \
    TLS_SENTINEL_TESTSSL_PATH=/usr/local/bin/testssl.sh \
    WRANGLER_SEND_METRICS=false \
    WRANGLER_CONFIG_DIR=/tmp/wrangler \
    WRANGLER_LOG_PATH=/tmp/wrangler/logs \
    MINIFLARE_REGISTRY_PATH=/tmp/wrangler/registry

USER tlsentinel
EXPOSE 3000 8787
VOLUME ["/data"]

CMD ["npm", "start"]
