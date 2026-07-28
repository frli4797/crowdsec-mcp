# Agent Instructions

These instructions apply to agents working in this repository.

## Mission

Keep `crowdsec-ops-mcp` a small, auditable MCP server for CrowdSec operations. Prefer changes that make CrowdSec reads clearer, safer, and easier to verify. Keep write behavior conservative.

## Boundaries

This MCP is CrowdSec-only.

Allowed integrations:

- CrowdSec LAPI for read-only decision data
- `cscli` for alert reads
- `cscli` command generation for reviewed single-IP write intents

Do not add direct access to:

- VictoriaMetrics
- VictoriaLogs
- Grafana
- Snort
- reverse proxy logs
- Docker socket or Docker API

For broader security investigations, agents should orchestrate this MCP alongside separate tools and keep evidence separated by source.

## Safety Rules

- Default to read-only tools and read-side improvements.
- Write tools may prepare commands only; they must not execute CrowdSec mutations.
- Keep write intents single-IP only.
- Do not add bulk ban, bulk unban, range ban, delete-all, parser mutation, scenario mutation, or profile mutation tools.
- Require a human-readable reason for any prepared ban or allow action.
- Prefer temporary allowlisting over permanent allowlisting.
- Preserve audit logging for prepared write intents.
- Do not expose API keys, machine credentials, URL-embedded credentials, or audit-log secrets in responses or logs.

## Development Workflow

- Read the existing code and docs before changing behavior.
- Keep changes scoped to the requested task.
- Follow existing patterns in `src/crowdsec_ops_mcp`.
- Add or update tests when behavior, schemas, parsing, recommendations, or tool outputs change.
- Run `.venv/bin/pytest` before committing when the virtualenv is available.
- Keep user-facing docs in `README.md` and `ONBOARDING.md`.
- Keep agent instructions here and prompt examples in `docs/agent-usage.md`.
- Keep contributor workflow details in `docs/development.md`, `docs/RELEASE.md`, and `docs/pull-request-rules.md`.

## Git Rules

- Do not push unless the user explicitly asks.
- Do not rewrite history unless explicitly requested.
- Do not revert user changes unless explicitly requested.
- Commit focused changes with conventional, descriptive messages.

## Useful Docs

- [docs/agent-usage.md](docs/agent-usage.md): agent prompt patterns and investigation guidance
- [docs/development.md](docs/development.md): local development workflow
- [docs/roadmap.md](docs/roadmap.md): project roadmap
- [docs/RELEASE.md](docs/RELEASE.md): release process
- [docs/pull-request-rules.md](docs/pull-request-rules.md): pull request rules
