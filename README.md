# crowdsec-ops-mcp

`crowdsec-ops-mcp` is a local MCP server for CrowdSec operations.

It exposes CrowdSec decisions, alerts, summaries, and safe single-IP action proposals to MCP clients. It is intentionally CrowdSec-only: it does not connect to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.

## What You Can Do

- Check whether the CrowdSec backend is reachable.
- Inspect active decisions and recent alerts for one IP.
- Summarize recent CrowdSec activity.
- Find top offending source IPs.
- Generate scenario-tuning proposals from repeated alert patterns.
- Prepare audited single-IP ban, allow, or unban commands for manual review.

Write tools do not execute CrowdSec changes. They validate a single IP, prepare a plausible `cscli` command for an operator to review, append the prepared intent to the JSON Lines audit log, and return `executed=false`.

## Getting Started

See [ONBOARDING.md](ONBOARDING.md) for installation, deployment, MCP client configuration, first tool calls, safety notes, and troubleshooting.

See [docs/decision-inventory-example.md](docs/decision-inventory-example.md) for example `decision_inventory` tool calls.

## Tools

- `crowdsec_health(include_sample_counts=false)`
- `inspect_ip(ip, window?)`
- `security_summary(window?)`
- `top_offenders(window?)`
- `recent_crowdsec_decisions(window?)`
- `decision_inventory(action?, origin?, scenario?, country?, asn?, ip?, limit?, expiring_soon_hours?, long_lived_days?)`
- `recent_crowdsec_alerts(window?)`
- `suggest_scenario(window?)`
- `unban_ip(ip, reason?, execute=false)`
- `allow_ip(ip, duration?, reason, execute=false)`
- `ban_ip(ip, duration?, reason, execute=false)`

## Configuration

| Variable | Purpose |
| --- | --- |
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI base URL. If omitted, `cscli` is used. |
| `CROWDSEC_LAPI_KEY` | CrowdSec LAPI key for decision reads. |
| `CSCLI_PATH` | Path to `cscli`, defaults to `cscli`. |
| `DEFAULT_WINDOW` | Default lookback window, defaults to `24h`. |
| `WRITE_AUDIT_LOG_PATH` | JSON Lines audit trail for prepared write intents, defaults to `crowdsec-write-audit.jsonl`. |
| `LOG_LEVEL` | Python log level, defaults to `INFO`. |

## Project Documents

- [ONBOARDING.md](ONBOARDING.md): user installation and first-use guide
- [docs/roadmap.md](docs/roadmap.md): project roadmap
