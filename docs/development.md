# Development

This guide contains local development workflow notes for `crowdsec-ops-mcp`.

## Bootstrap A Worktree

Bootstrap a fresh worktree with local runtime files:

```bash
./scripts/bootstrap_worktree.sh
```

This creates `docker-compose.yaml`, `.env`, and `.venv`, then installs the package with development dependencies. For Git worktrees, it copies `docker-compose.yaml` or `docker-compose.yml` and `.env` from the main checkout when those files exist, so local Compose settings and secrets follow the worktree without being committed. Existing files are left in place.

To copy from a specific source checkout:

```bash
MAIN_WORKTREE_DIR=/path/to/crowdsec-mcp ./scripts/bootstrap_worktree.sh
```

## Local Python Environment

Use a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
crowdsec-ops-mcp
```

Or use `uv`:

```bash
uv venv
uv pip install -e ".[dev]"
uv run pytest
uv run crowdsec-ops-mcp
```

## Local Docker Images

Docker remains the recommended deployment path for the first version. Target environments should pull the published GHCR image; local image builds are for development and CI validation.

Image tags:

- `ghcr.io/frli4797/crowdsec-ops-mcp:0.1.1` for an exact release
- `ghcr.io/frli4797/crowdsec-ops-mcp:latest` for the latest release
- `ghcr.io/frli4797/crowdsec-ops-mcp:edge` or `:main` for the latest `main` build
- `ghcr.io/frli4797/crowdsec-ops-mcp:pr-123` for a same-repository PR preview image

Docker tags cannot contain `/` or `#`, so use `:edge`, `:main`, and `:pr-123`.
