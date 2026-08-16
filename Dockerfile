FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -u 10001 sentinel && \
    mkdir -p /app/data /app/logs /app/rules /app/src && \
    chown -R sentinel:sentinel /app

COPY --chown=sentinel:sentinel src/ /app/src/
COPY --chown=sentinel:sentinel rules/ /app/rules/

USER sentinel

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/api/v1/telemetry/health || exit 1

CMD ["sh", "-c", "uvicorn src.telemetry_buffer:app --host 0.0.0.0 --port ${PORT:-10000}"]
