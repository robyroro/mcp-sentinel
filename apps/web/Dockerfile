FROM node:22-bookworm-slim AS dependencies
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm install --frozen-lockfile

FROM dependencies AS build
COPY apps/web ./apps/web
ARG SENTINEL_API_ORIGIN=http://api:8000
ENV NEXT_TELEMETRY_DISABLED=1 \
    SENTINEL_API_ORIGIN=$SENTINEL_API_ORIGIN
RUN pnpm --dir apps/web build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
WORKDIR /app
RUN groupadd --gid 65532 sentinel && useradd --uid 65532 --gid 65532 sentinel
COPY --from=build --chown=65532:65532 /app/apps/web/.next/standalone ./
COPY --from=build --chown=65532:65532 /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=65532:65532 /app/apps/web/public ./apps/web/public
USER 65532:65532
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
