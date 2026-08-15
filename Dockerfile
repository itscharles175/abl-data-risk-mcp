# syntax=docker/dockerfile:1.7

ARG NODE_BUILD_IMAGE=node:24.13.1-bookworm-slim@sha256:a81a03dd965b4052269a57fac857004022b522a4bf06e7a739e25e18bce45af2
ARG NODE_RUNTIME_IMAGE=gcr.io/distroless/nodejs24-debian13@sha256:fbbdda866ea71aef98c4abece17e3d61fbf820cc2ef3961522caa2478716171a

FROM ${NODE_BUILD_IMAGE} AS build

ARG PNPM_VERSION=11.16.0

ENV CI=true \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:${PATH}

WORKDIR /workspace

RUN npm install --global "pnpm@${PNPM_VERSION}"

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=abl-mcp-pnpm,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
COPY scripts/container-entrypoint.mjs scripts/container-healthcheck.mjs ./scripts/

RUN pnpm run build && \
    pnpm prune --prod && \
    pnpm store prune && \
    install -d -m 0700 /workspace/runtime-data/control /workspace/runtime-data/artifacts

FROM ${NODE_RUNTIME_IMAGE} AS runtime

ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="ABL Data & Risk MCP" \
      org.opencontainers.image.description="Governed ABL and loan-tape analytics MCP server" \
      org.opencontainers.image.source="https://github.com/itscharles175/abl-data-risk-mcp" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="UNLICENSED"

ENV NODE_ENV=production \
    ABL_MCP_HOST=127.0.0.1 \
    ABL_MCP_PORT=3333 \
    ABL_MCP_CONTROL_DB_PATH=/var/lib/abl/control/control.sqlite3 \
    ABL_MCP_JOB_DB_PATH=/var/lib/abl/control/jobs.sqlite3 \
    ABL_MCP_SECURITY_DB_PATH=/var/lib/abl/control/security.sqlite3 \
    ABL_MCP_ARTIFACT_ROOT=/var/lib/abl/artifacts

WORKDIR /app

COPY --from=build --chown=65532:65532 --chmod=0444 /workspace/package.json ./package.json
COPY --from=build --chown=65532:65532 --chmod=0555 /workspace/node_modules ./node_modules
COPY --from=build --chown=65532:65532 --chmod=0555 /workspace/dist ./dist
COPY --from=build --chown=65532:65532 --chmod=0555 /workspace/scripts ./scripts
COPY --from=build --chown=65532:65532 --chmod=0700 /workspace/runtime-data/ /var/lib/abl/

USER 65532:65532

EXPOSE 3333
STOPSIGNAL SIGTERM

# The image defaults to the safe local/sidecar STDIO transport. Compose and
# Kubernetes select the guarded serve-remote entrypoint and fail closed until
# the authenticated remote runtime and its policy inputs are present.
CMD ["dist/cli.js", "serve", "stdio"]
