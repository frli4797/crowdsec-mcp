# crowdsec-ops-mcp

Local MCP server for CrowdSec operations in a homelab security stack.

This MCP is intentionally CrowdSec-only. Codex should orchestrate full investigations by combining this server with separate MCPs for metrics, logs, and Grafana. That keeps credentials scoped and avoids giving this container direct access to VictoriaMetrics, VictoriaLogs, or Grafana.

## Tools

- `inspect_ip(ip, window?)`
- `security_summary(window?)`
- `top_offenders(window?)`
- `recent_crowdsec_decisions(window?)`
- `recent_crowdsec_alerts(window?)`
- `suggest_scenario(window?)`
- `unban_ip(ip, reason?, execute=false)`
- `allow_ip(ip, duration?, reason, execute=false)`
- `ban_ip(ip, duration?, reason, execute=false)`

## Orchestration Model

Use this MCP for CrowdSec state and tightly scoped CrowdSec operator actions:

- active decisions
- recent CrowdSec alerts
- source IPs, countries, ASNs, scenarios, timestamps
- dry-run ban, unban, and temporary allow actions
- YAML proposals for scenario tuning

Use other MCPs for adjacent evidence:

- logs MCP: Snort alerts, AppSec events, NPM/reverse-proxy logs, raw CrowdSec logs
- metrics MCP: bouncer health, remediation counters, AppSec block volume
- Grafana MCP: dashboard links and audit annotations

## Configuration

Environment variables:

| Variable | Purpose |
| --- | --- |
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI base URL. If omitted, `cscli` is used |
| `CROWDSEC_LAPI_KEY` | CrowdSec LAPI key for decision reads |
| `CSCLI_PATH` | Path to `cscli`, defaults to `cscli` |
| `DEFAULT_WINDOW` | Default lookback window, defaults to `24h` |
| `WRITE_EXECUTE_DEFAULT` | Keep `false` unless you really want write tools to execute by default |

Write actions currently use `cscli` so they can rely on the local CrowdSec operator interface and avoid expanding LAPI permissions too early.

## Local Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Run the MCP server over stdio:

```bash
crowdsec-ops-mcp
```

## Docker

```bash
docker compose -f docker-compose.example.yml up --build
```

Mounting the Docker socket is deliberately avoided. Prefer CrowdSec LAPI credentials for reads and a narrowly scoped `cscli` installation or wrapper for writes.

## Example Tool Calls

```json
{"tool": "inspect_ip", "arguments": {"ip": "203.0.113.10", "window": "24h"}}
```

```json
{"tool": "ban_ip", "arguments": {"ip": "203.0.113.10", "duration": "4h", "reason": "confirmed repeated exploit attempts"}}
```

The second call returns a dry-run summary. Add `"execute": true` to run it.

## Safety Model

- Read-only CrowdSec tools are the default workflow.
- Write tools only operate on a single IP.
- No bulk ban, bulk unban, or delete-all operation is exposed.
- Parser, scenario, profile, and external rule changes are generated only as proposals.
- Temporary allowlisting is preferred over permanent allowlisting.
- Executed write actions return an audit hint so Codex can create a Grafana annotation through the Grafana MCP.
