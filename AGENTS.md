# Agent Instructions

These instructions apply to agents working in this repository.

## Mission

Keep `crowdsec-ops-mcp` a small, auditable MCP server for CrowdSec operations. Prefer changes that make CrowdSec reads clearer, safer, and easier to verify. Keep write behavior conservative.

## Boundaries

This MCP is CrowdSec-only.

Allowed integrations:

- CrowdSec LAPI for read-only decision data
- CrowdSec LAPI machine auth for alert reads
- supported CrowdSec API-level access for scoped reads or writes
- CrowdSec LAPI machine auth for gated, audited single-scenario simulation writes
- `cscli` command generation for reviewed single-IP decision intents

Prefer API-level access over remote command execution. Do not add remote `cscli` execution when a supported CrowdSec API path can provide the capability. If `cscli` is used, keep it to local operator command generation unless a future design explicitly documents why no API-level alternative exists.

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
- Single-IP write tools may prepare commands only; they must not execute CrowdSec IP decision mutations.
- API write tools are allowed only when they are explicitly scoped, gated by `WRITE_OPERATIONS_ENABLED=true`, machine-authenticated, and audited.
- Keep IP write intents single-IP only.
- Keep scenario simulation writes single-scenario only.
- Before calling a scenario simulation write tool, ask the user for the exact confirmation phrase `confirm scenario simulation <action> <scenario>` and pass it as `user_confirmation`.
- Do not add bulk ban, bulk unban, range ban, delete-all, parser mutation, scenario mutation, or profile mutation tools.
- Require a human-readable reason for any prepared ban, allow, unban, or scenario simulation write.
- Prefer temporary allowlisting over permanent allowlisting.
- Preserve audit logging for prepared write intents and executed API writes.
- Do not expose API keys, machine credentials, URL-embedded credentials, or audit-log secrets in responses or logs.

## Development Workflow

- Read the existing code and docs before changing behavior.
- Keep changes scoped to the requested task.
- Follow existing patterns in `src/crowdsec_ops_mcp`.
- Add or update tests when behavior, schemas, parsing, recommendations, or tool outputs change.
- Run `.venv/bin/pytest` before committing when the virtualenv is available.

## Documentation Structure

Keep documentation organized by audience and purpose. When adding or moving information, choose the narrowest document that matches the reader's goal.

Use `README.md` as the user-facing front door:

- short project description
- what the MCP can do
- safety headline for prepared IP actions and gated API writes
- tool list
- configuration variable summary
- links to deeper user docs

Do not put local development workflow, release process, PR rules, agent instructions, long architecture notes, or prompt examples in `README.md`.

Use `ONBOARDING.md` for user installation and first use:

- prerequisites
- recommended deployment
- MCP client configuration
- first tool calls
- user-facing safety checklist
- troubleshooting

Do not put contributor workflow, CI details, release mechanics, or agent prompt strategy in `ONBOARDING.md`.

Use `AGENTS.md` for durable repo-level instructions to coding agents:

- project mission and boundaries
- safety rules for implementation work
- development workflow expectations
- documentation placement rules
- git behavior

Keep `AGENTS.md` concise and directive. Avoid duplicating long examples from other docs.

Use `docs/agent-usage.md` for agent runtime guidance:

- prompt patterns
- evidence handling
- cross-system investigation guidance
- expected agent output shape

Use `docs/development.md` for contributor and local development workflow:

- worktree bootstrap
- virtualenv or `uv` setup
- local test commands
- local image and development tag notes

Use `docs/roadmap.md` for project direction:

- future read-side tool ideas
- write-operation planning
- shared reliability and output-contract work
- implementation order and status notes

Use `docs/RELEASE.md`, `docs/release-notes-template.md`, and `docs/pull-request-rules.md` only for release and contribution process details:

- versioning
- release steps
- image publishing behavior
- rollback notes
- PR expectations
- release-note structure

When documentation overlaps, prefer linking over copying. If the same content appears in multiple docs, keep the user-facing version brief and move detailed operational guidance to the specialized doc.

## Git Rules

- Do not push unless the user explicitly asks.
- Do not rewrite history unless explicitly requested.
- Do not revert user changes unless explicitly requested.
- Commit focused changes with conventional, descriptive messages.
- When creating a pull request, always use the required metadata contract from `docs/pull-request-rules.md`: title prefix `Feature`, `Fix`, `Chore`, `Docs`, `CI/CD`, or `Release`, plus body sections `## Summary`, `## Type`, and `## Validation`.

## Useful Docs

- [docs/agent-usage.md](docs/agent-usage.md): agent prompt patterns and investigation guidance
- [docs/development.md](docs/development.md): local development workflow
- [docs/roadmap.md](docs/roadmap.md): project roadmap
- [docs/RELEASE.md](docs/RELEASE.md): release process
- [docs/pull-request-rules.md](docs/pull-request-rules.md): pull request rules
