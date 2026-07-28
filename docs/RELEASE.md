# Release Process

Releases are tag-driven.

## Versioning

Use semantic versioning:

- `MAJOR`: breaking MCP tool contract or safety model changes
- `MINOR`: new backwards-compatible tools or behavior
- `PATCH`: fixes, docs, CI, and internal maintenance

The tag must match the package version:

- `pyproject.toml`: `project.version = "0.1.1"`
- `src/crowdsec_ops_mcp/__init__.py`: `__version__ = "0.1.1"`
- Git tag: `v0.1.1`

## Release Steps

1. Update the version in `pyproject.toml` and `src/crowdsec_ops_mcp/__init__.py`.
2. Update release notes using `docs/release-notes-template.md`.
3. Open a PR using the PR template.
4. Merge to `main` after CI passes.
5. Create and push a signed or annotated tag:

```bash
git tag -a v0.1.1 -m "v0.1.1"
git push origin v0.1.1
```

GitHub Actions will:

- verify the tag matches the package version
- run tests
- build the Python package
- build and push the Docker image to GHCR
- create a GitHub release with generated notes

## Build Caching

CI uses:

- `actions/setup-python` pip caching keyed from `pyproject.toml`
- Docker BuildKit cache mounts for pip during image builds
- `docker/build-push-action` GitHub Actions layer cache for PR, push, and release builds

## Images

Release tags publish:

- `ghcr.io/<owner>/crowdsec-ops-mcp:<version>`
- `ghcr.io/<owner>/crowdsec-ops-mcp:<major>.<minor>`
- `ghcr.io/<owner>/crowdsec-ops-mcp:latest`

Prefer the exact version tag in production.

Example compose deployments should use the published image instead of `build: .` so target hosts do not need the source tree or build toolchain.

Main branch pushes publish moving development tags:

- `ghcr.io/<owner>/crowdsec-ops-mcp:edge`
- `ghcr.io/<owner>/crowdsec-ops-mcp:main`

Same-repository non-Dependabot pull requests publish preview images:

- `ghcr.io/<owner>/crowdsec-ops-mcp:pr-123`

Docker tags cannot contain `/` or `#`, so use `:edge`, `:main`, and `:pr-123` rather than `:main/edge` or `:PR#123`.

## Rollback

Redeploy the previous known-good image tag. Avoid deleting release tags unless the release exposed credentials or contains a severe publishing mistake.
