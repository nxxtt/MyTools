# === Stage 1: Builder ===
FROM python:3.14-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry
WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.in-project true \
    && poetry install --only main --no-root --no-interaction

COPY src/ src/
COPY README.MD ./
RUN poetry install --only main --no-interaction

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
