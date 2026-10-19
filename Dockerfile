# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 1000 app
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src

# --- Runtime image: only what the tool needs -------------------------------------------------
FROM base AS runtime
RUN pip install . && rm -rf build src/*.egg-info
USER app
ENTRYPOINT ["tracer"]

# --- Test image: dev tools and tests, never shipped ------------------------------------------
FROM base AS test
RUN pip install ".[dev]"
COPY tests ./tests
ENV MYPY_CACHE_DIR=/tmp/mypy RUFF_CACHE_DIR=/tmp/ruff
USER app
ENTRYPOINT ["sh", "-c", "ruff check src tests && mypy src && pytest -q -p no:cacheprovider"]
