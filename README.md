# crowdsec-ops-mcp

Local MCP server for CrowdSec operations.

This MCP is intentionally CrowdSec-only. It does not connect to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker. Agents are the orchestrators: they combine this MCP's CrowdSec state with evidence from separate metrics, logs, and dashboard MCPs when a wider investigation needs it.

See [ONBOARDING.md](ONBOARDING.md) for installation, deployment, client configuration, and first-use instructions.

See [docs/RELEASE.md](docs/RELEASE.md) and [docs/pull-request-rules.md](docs/pull-request-rules.md) for CI/CD, release, and PR rules.

## Tools

- `crowdsec_health(include_sample_counts=false)`
- `inspect_ip(ip, window?)`
- `security_summary(window?)`
- `top_offenders(window?)`
- `recent_crowdsec_decisions(window?)`
- `recent_crowdsec_alerts(window?)`
- `suggest_scenario(window?)`
- `unban_ip(ip, reason?, execute=false)`
- `allow_ip(ip, duration?, reason, execute=false)`
- `ban_ip(ip, duration?, reason, execute=false)`

## Architecture Boundary

This server owns one responsibility: expose CrowdSec state and tightly scoped CrowdSec operator actions through MCP.

It may access:

- CrowdSec LAPI for read-only decision data
- `cscli` for alert reads and potential single-IP write command generation

It must not access:

- VictoriaMetrics
- VictoriaLogs
- Grafana
- Snort directly
- reverse proxy logs
- the Docker socket

Agents should perform cross-system investigations by calling this MCP alongside separate MCPs for logs, metrics, and dashboards. This keeps service credentials scoped and makes each MCP auditable on its own.

## Configuration

Environment variables:

| Variable | Purpose |
| --- | --- |
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI base URL. If omitted, `cscli` is used |
| `CROWDSEC_LAPI_KEY` | CrowdSec LAPI key for decision reads |
| `CSCLI_PATH` | Path to `cscli`, defaults to `cscli` |
| `DEFAULT_WINDOW` | Default lookback window, defaults to `24h` |
| `WRITE_AUDIT_LOG_PATH` | JSON Lines audit trail for prepared write intents, defaults to `crowdsec-write-audit.jsonl` |
| `LOG_LEVEL` | Python log level, defaults to `INFO`; use `DEBUG` to echo MCP client tool activity |

Write tools do not execute CrowdSec changes. They validate a single IP, prepare a plausible `cscli` command for an operator to review, and append the prepared intent to the JSON Lines audit log.

Logs are written to stderr so stdio transport messages on stdout stay valid. Startup logs include version, transport, backend mode, and exposed tool capabilities. LAPI reachability failures are logged at `ERROR`.

Use `crowdsec_health` when empty or incomplete results need explanation. It reports the selected backend mode, LAPI URL/key presence and reachability without exposing API keys or embedded URL credentials, `cscli` path availability, default lookback window, write audit log path, and exposed MCP tool capabilities. Set `include_sample_counts=true` to also fetch small decision and alert counts.

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

## Deployment

```bash
docker compose -f docker-compose.example.yml pull
docker compose -f docker-compose.example.yml up -d
```

Docker is the first supported deployment model. Run it on the same Docker network as CrowdSec, or on a host that can reach CrowdSec LAPI. Write tools only prepare potential `cscli` commands for manual operator review.

The example compose file only accepts CrowdSec-related configuration. Mounting the Docker socket is deliberately avoided.

For the private GHCR image, log in on the target host before pulling:

```bash
echo "<github-token-with-read-packages>" | docker login ghcr.io -u "<github-username>" --password-stdin
```

## Example Tool Calls

```json
{"tool": "inspect_ip", "arguments": {"ip": "203.0.113.10", "window": "24h"}}
```

```json
{"tool": "crowdsec_health", "arguments": {"include_sample_counts": true}}
```

```json
{"tool": "ban_ip", "arguments": {"ip": "203.0.113.10", "duration": "4h", "reason": "confirmed repeated exploit attempts"}}
```

The second call returns a prepared, audited `potential_cscli_command`. The MCP does not run it, even if `"execute": true` is sent.

## Safety Model

- Read-only CrowdSec tools are the default workflow.
- Write tools only prepare potential commands for a single IP.
- Write tools never execute `cscli` write actions.
- No bulk ban, bulk unban, or delete-all operation is exposed.
- Parser, scenario, and profile changes are generated only as proposals.
- Temporary allowlisting is preferred over permanent allowlisting.
- Prepared write intents are appended to the JSON Lines audit log and returned to the caller with `executed=false`.
