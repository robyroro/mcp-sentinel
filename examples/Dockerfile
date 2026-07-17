FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SENTINEL_DEMO_WORKSPACE=/workspace/project
RUN groupadd --gid 65532 sentinel && useradd --uid 65532 --gid 65532 --create-home sentinel \
    && pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn>=0.34,<1"
WORKDIR /app
COPY examples/demo_mcp_server.py ./demo_mcp_server.py
RUN mkdir -p /workspace/project && chown -R sentinel:sentinel /workspace /app
USER 65532:65532
ENTRYPOINT ["python", "/app/demo_mcp_server.py"]
