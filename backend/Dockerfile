# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 – builder: compile wheels so the runtime image stays small
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build-time system deps (gcc needed for some wheels)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2 – runtime: lean production image
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN useradd --no-create-home --shell /bin/false --uid 1001 appuser

WORKDIR /app

# Copy pre-built wheels from builder and install (no gcc needed)
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

# Copy application source
COPY app ./app

# Create dirs owned by appuser
RUN mkdir -p data reports \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Healthcheck (used by docker-compose depends_on condition)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

# 2 uvicorn workers in production; override via WORKERS env var
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-2}"]
