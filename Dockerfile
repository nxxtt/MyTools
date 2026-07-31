# === Stage 1: Builder ===
FROM python:3.14-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /uvx /bin/
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ src/
COPY README.MD ./
RUN uv sync --frozen --no-dev

# === Stage 2: Runtime ===
FROM python:3.14-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4 libfreetype6 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH"

RUN useradd --create-home mytools
USER mytools

CMD ["mytools", "--help"]
