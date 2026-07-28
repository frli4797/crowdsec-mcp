# syntax=docker/dockerfile:1.7

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --root-user-action=ignore .

USER nobody
ENTRYPOINT ["crowdsec-ops-mcp"]
