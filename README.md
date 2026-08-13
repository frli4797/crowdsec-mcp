# crowdsec-ops-mcp

`crowdsec-ops-mcp` is a local MCP server for CrowdSec operations.

It exposes CrowdSec decisions, alerts, summaries, safe single-IP action proposals, and scenario simulation proposals to MCP clients. It is intentionally CrowdSec-only: it does not connect to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.

Supported runtime reads use CrowdSec LAPI. Decision reads use a bouncer API key. Alert reads require optional CrowdSec machine credentials because bouncer keys can only read decisions. Actual `cscli` reads or `cscli` execution are not supported by the MCP today; write tools only generate `cscli` command text for an operator to review and run outside the MCP if appropriate.

## Contents

- [What You Can Do](#what-you-can-do)
- [Getting Started](#getting-started)
- [Tools](#tools)
- [Configuration](#configuration)
- [Project Documents](#project-documents)

## What You Can Do

- Check whether the CrowdSec backend is reachable.
- Inspect active decisions and recent alerts for one IP.
- Summarize recent CrowdSec activity.
- Find top offending source IPs.
- Generate scenario-tuning proposals from repeated alert patterns.
- Prepare audited single-IP ban, allow, or unban commands for manual review.
- Prepare audited commands to move one scenario into or out of simulation for manual review.

Write tools do not execute CrowdSec changes. They validate the requested IP or scenario, prepare a plausible `cscli` command for an operator to review, append the prepared intent to the JSON Lines audit log, and return `executed=false`. Scenario simulation responses also include non-secret auth context so agents can distinguish LAPI machine-auth availability from the local `cscli` simulation command being proposed.

For future capabilities, prefer supported CrowdSec API-level access over remote `cscli` execution. `cscli` text in responses is for local operator review unless a future design explicitly documents why no API-level alternative exists.

## Getting Started

See [ONBOARDING.md](ONBOARDING.md) for installation, deployment, MCP client configuration, first tool calls, safety notes, and troubleshooting.

See [docs/decision-inventory-example.md](docs/decision-inventory-example.md) for example `decision_inventory` tool calls.

See [docs/decision-gap-report-example.md](docs/decision-gap-report-example.md) for example `decision_gap_report` tool calls.

## Tools

- `crowdsec_health(include_sample_counts=false)`
- `inspect_ip(ip, window?)`
- `security_summary(window?)`
- `top_offenders(window?)`
- `recent_crowdsec_decisions(window?)`
- `decision_inventory(action?, origin?, scenario?, country?, asn?, ip?, limit?, expiring_soon_hours?, long_lived_days?)`
- `recent_crowdsec_alerts(window?)`
- `decision_gap_report(window?, repeat_threshold?, noisy_scenario_threshold?, expiring_soon_hours?, limit?)`
- `suggest_scenario(window?)`
- `unban_ip(ip, reason?, execute=false)`
- `allow_ip(ip, duration?, reason, execute=false)`
- `ban_ip(ip, duration?, reason, execute=false)`
- `enable_scenario_simulation(scenario, reason, execute=false)`
- `disable_scenario_simulation(scenario, reason, execute=false)`

## Configuration

| Variable | Purpose |
| --- | --- |
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI base URL. Required for supported read operations. |
| `CROWDSEC_LAPI_KEY` | CrowdSec LAPI key for decision reads. |
| `CROWDSEC_LAPI_MACHINE_ID` | Optional CrowdSec machine ID for read-only alert list access. |
| `CROWDSEC_LAPI_MACHINE_PASSWORD` | Optional CrowdSec machine password for read-only alert list access. |
| `CSCLI_PATH` | Command name/path used only when formatting prepared `potential_cscli_command` text. The MCP does not run `cscli`. |
| `DEFAULT_WINDOW` | Default lookback window, defaults to `24h`. |
| `WRITE_AUDIT_LOG_PATH` | JSON Lines audit trail for prepared write intents, defaults to `crowdsec-write-audit.jsonl`. |
| `LOG_LEVEL` | Python log level, defaults to `INFO`. |

## Project Documents

- [ONBOARDING.md](ONBOARDING.md): user installation and first-use guide
- [CHANGELOG.md](CHANGELOG.md): version history
- [docs/decision-inventory-example.md](docs/decision-inventory-example.md): example `decision_inventory` tool calls
- [docs/decision-gap-report-example.md](docs/decision-gap-report-example.md): example `decision_gap_report` tool calls
- [docs/snort-crowdsec-scenarios.md](docs/snort-crowdsec-scenarios.md): example CrowdSec scenarios for Snort-derived alert patterns
- [docs/agent-usage.md](docs/agent-usage.md): agent prompt patterns and investigation guidance
- [docs/development.md](docs/development.md): local development workflow
- [docs/roadmap.md](docs/roadmap.md): project roadmap
- [docs/release-notes/v0.3.0.md](docs/release-notes/v0.3.0.md): release notes for `v0.3.0`
- [docs/release-notes/v0.2.1.md](docs/release-notes/v0.2.1.md): release notes for `v0.2.1`
- [docs/RELEASE.md](docs/RELEASE.md): release process
- [docs/pull-request-rules.md](docs/pull-request-rules.md): pull request rules
- [docs/release-notes-template.md](docs/release-notes-template.md): release notes template
