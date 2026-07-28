# Agent Instructions

These instructions apply to agents working in this repository.

## Project Boundary

`crowdsec-ops-mcp` is intentionally CrowdSec-only.

The MCP may access:

- CrowdSec LAPI for read-only decision data
- `cscli` for alert reads and potential single-IP write command generation

The MCP must not access:

- VictoriaMetrics
- VictoriaLogs
- Grafana
- Snort directly
- reverse proxy logs
- the Docker socket

For cross-system investigations, agents should combine this MCP with separate logs, metrics, and dashboard tools while keeping evidence separated by source.

## Safety Model

- Read-only CrowdSec tools are the default workflow.
- Write tools only prepare potential commands for a single IP.
- Write tools never execute `cscli` write actions.
- No bulk ban, bulk unban, or delete-all operation is exposed.
- Parser, scenario, and profile changes are generated only as proposals.
- Temporary allowlisting is preferred over permanent allowlisting.
- Prepared write intents are appended to the JSON Lines audit log and returned to the caller with `executed=false`.

## Useful Docs

- [docs/agent-usage.md](docs/agent-usage.md): prompt patterns and investigation guidance
- [docs/development.md](docs/development.md): local development workflow
- [docs/roadmap.md](docs/roadmap.md): project roadmap
- [docs/RELEASE.md](docs/RELEASE.md): release process
- [docs/pull-request-rules.md](docs/pull-request-rules.md): pull request rules
