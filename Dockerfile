FROM ghcr.io/astral-sh/uv:python3.12-alpine AS deps

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12-alpine

WORKDIR /app
COPY --from=deps /app/.venv /app/.venv
COPY unifi2ipam.py ./

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "unifi2ipam.py"]
