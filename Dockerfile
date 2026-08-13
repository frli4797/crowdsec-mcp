# syntax=docker/dockerfile:1.7

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md /app/

RUN --mount=type=cache,target=/root/.cache/pip \
    python -c "import pathlib, tomllib; pyproject = tomllib.loads(pathlib.Path('pyproject.toml').read_text()); deps = pyproject['project']['dependencies'] + pyproject['build-system']['requires']; pathlib.Path('/tmp/requirements.txt').write_text('\n'.join(deps) + '\n')" \
    && pip install --root-user-action=ignore -r /tmp/requirements.txt

COPY src /app/src

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --root-user-action=ignore --no-build-isolation --no-deps .

RUN mkdir -p /var/log/crowdsec-ops-mcp \
    && chown nobody:nogroup /var/log/crowdsec-ops-mcp

USER nobody
ENTRYPOINT ["crowdsec-ops-mcp"]
