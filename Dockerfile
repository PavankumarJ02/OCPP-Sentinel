# =============================================================================
# Dockerfile — Multi-stage build for OCPP Sentinel
# =============================================================================
#
# LEARNING NOTE: MULTI-STAGE DOCKER BUILDS
# 1. Builder stage: Installs compiler tools and builds Python dependencies.
# 2. Runner stage: Copies ONLY the installed packages and application code.
#
# Result: A secure, lightweight container image (~300MB vs 1.5GB+).
# =============================================================================

# ---- Stage 1: Builder ----
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies (needed for compiling C-extensions like chromadb / hnswlib)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project specification
COPY pyproject.toml .
COPY src/ src/
COPY README.md .

# Install dependencies into wheels directory
RUN pip install --no-cache-dir --upgrade pip wheel setuptools
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels .

# ---- Stage 2: Final Runtime ----
FROM python:3.11-slim AS runner

WORKDIR /app

# Copy built wheels from builder stage
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application source code and data
COPY src/ src/
COPY data/ data/
COPY pyproject.toml .
COPY README.md .

# Create logs directory
RUN mkdir -p logs

# Index ChromaDB knowledge base during image build
RUN python -m ocpp_sentinel.knowledge.loader

# Expose port 8000
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PORT=8000

# Run Uvicorn ASGI server
CMD ["uvicorn", "ocpp_sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
