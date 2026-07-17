FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 sentinel \
    && useradd --uid 65532 --gid 65532 --create-home sentinel

WORKDIR /app
COPY pyproject.toml ./
COPY alembic.ini ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/cli ./apps/cli
COPY apps/worker ./apps/worker
RUN python -m pip install ".[postgres,worker]"

RUN mkdir -p /data /app/reports/generated /app/audit-output \
    && chown -R sentinel:sentinel /data /app
USER 65532:65532

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --retries=5 CMD curl -fsS http://localhost:8000/api/v1/health || exit 1
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && exec uvicorn mcp_sentinel_api.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
