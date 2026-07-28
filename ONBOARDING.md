# Onboarding

This guide explains how to install, run, and use `crowdsec-ops-mcp`.

## What This MCP Does

`crowdsec-ops-mcp` exposes CrowdSec state and tightly scoped single-IP operator action proposals to an MCP client.

It only talks to CrowdSec. Agents are responsible for combining this MCP with separate logs, metrics, and dashboard MCPs when a broader investigation needs more context.

## Prerequisites

- Docker and Docker Compose
- Network access from this container to CrowdSec LAPI
- A CrowdSec LAPI key for read access
- Optional: `cscli` path configuration if you want generated command text to match a non-default local path

Do not mount the Docker socket into this container.

## Recommended Deployment

Run the MCP near CrowdSec, usually on the same Docker network as the CrowdSec service.

Because the repository and package are private, authenticate Docker to GHCR on the target host before pulling:

```bash
echo "<github-token-with-read-packages>" | docker login ghcr.io -u "<github-username>" --password-stdin
```

The token needs `read:packages`. For private packages, it may also need repository access depending on how the package permissions are configured.

1. Copy the example compose file:

```bash
cp docker-compose.example.yml docker-compose.yml
```

2. Create an `.env` file:

```bash
CROWDSEC_LAPI_KEY=replace-with-your-lapi-key
```

3. Confirm the CrowdSec URL and network in `docker-compose.yml`:

```yaml
environment:
  CROWDSEC_LAPI_URL: http://crowdsec:8080
networks:
  - security
```

4. Pull and start the published container:

```bash
docker compose pull
docker compose up -d
```

5. Check logs:

```bash
docker compose logs -f crowdsec-ops-mcp
```

## MCP Client Configuration

Configure your MCP client to launch the containerized server over stdio.

Example command shape:

```json
{
  "mcpServers": {
    "crowdsec-ops": {
      "command": "docker",
      "args": ["compose", "run", "--rm", "crowdsec-ops-mcp"]
    }
  }
}
```

If your MCP client runs from a different directory, use an absolute compose file path:

```json
{
  "mcpServers": {
    "crowdsec-ops": {
      "command": "docker",
      "args": [
        "compose",
        "-f",
        "/path/to/crowdsec-mcp/docker-compose.yml",
        "run",
        "--rm",
        "crowdsec-ops-mcp"
      ]
    }
  }
}
```

## First Tool Calls

Inspect one IP:

```json
{
  "tool": "inspect_ip",
  "arguments": {
    "ip": "203.0.113.10",
    "window": "24h"
  }
}
```

Get a CrowdSec summary:

```json
{
  "tool": "security_summary",
  "arguments": {
    "window": "24h"
  }
}
```

Prepare a potential manual ban command:

```json
{
  "tool": "ban_ip",
  "arguments": {
    "ip": "203.0.113.10",
    "duration": "4h",
    "reason": "confirmed repeated exploit attempts"
  }
}
```

The response includes a `potential_cscli_command` and appends the prepared intent to the write audit log. The MCP does not execute the command, even if a legacy `execute` flag is sent:

```json
{
  "tool": "ban_ip",
  "arguments": {
    "ip": "203.0.113.10",
    "duration": "4h",
    "reason": "confirmed repeated exploit attempts",
    "execute": true
  }
}
```

## Efficient Agent Prompts

Use prompts that name the target, the time window, and the desired decision. Remind the agent that this MCP is CrowdSec-only and that other evidence should come from separate MCPs.

Inspect an IP with a recommendation:

```text
Inspect 203.0.113.10 in CrowdSec for the last 24h. Show active decisions, recent alerts, scenarios, country/ASN, and timestamps. Recommend ignore, monitor, keep ban, unban, temporary allow, or manual ban. Do not execute any write action.
```

Investigate an IP across the wider stack:

```text
Investigate 203.0.113.10 for the last 24h. Use crowdsec-ops-mcp only for CrowdSec decisions and alerts. Use the logs MCP for Snort/AppSec/reverse-proxy evidence, the metrics MCP for remediation health, and the dashboard MCP only for links or annotations. Summarize evidence separately by source and make a final operator recommendation. Do not execute changes.
```

Review current CrowdSec posture:

```text
Summarize CrowdSec activity for the last 24h. Include active decision count, recent alert count, top source IPs, top countries/ASNs, top scenarios, and suspicious trends. Keep the answer focused on CrowdSec data only.
```

Prepare a safe ban:

```text
Check whether 203.0.113.10 should be manually banned for 4h. First inspect CrowdSec evidence for the last 24h, then prepare a potential cscli ban command with a clear reason if warranted. Do not execute changes.
```

Prepare a temporary allow:

```text
Inspect 198.51.100.25 in CrowdSec and decide whether a temporary allow is safer than unbanning. If allowlisting is justified, prepare only a potential allow_ip command for 1h with the reason. Do not execute changes.
```

Prepare an operator-reviewed command:

```text
Prepare the previously reviewed ban command for 203.0.113.10 for 4h with reason "confirmed repeated exploit attempts". Use only the single-IP ban tool. Do not perform any bulk action.
```

Suggest tuning without applying it:

```text
Analyze recent CrowdSec alerts from the last 7d and suggest scenario tuning if there is a repeated pattern. Return proposed YAML only, with evidence, risk, expected noise, and recommended simulation period. Do not modify CrowdSec files.
```

Good prompts usually include:

- a specific IP or window
- whether write proposals are wanted
- whether the answer should stay CrowdSec-only or orchestrate other MCPs
- the expected output, such as recommendation, potential command, or YAML proposal

## Local Development

Bootstrap a fresh worktree with local runtime files:

```bash
./scripts/bootstrap_worktree.sh
```

This creates `docker-compose.yaml`, `.env`, and `.venv`, then installs the package with development dependencies. For Git worktrees, it copies `docker-compose.yaml` or `docker-compose.yml` and `.env` from the main checkout when those files exist, so local Compose settings and secrets follow the worktree without being committed. Existing files are left in place.

To copy from a specific source checkout:

```bash
MAIN_WORKTREE_DIR=/path/to/crowdsec-mcp ./scripts/bootstrap_worktree.sh
```

Use a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
crowdsec-ops-mcp
```

Or use `uv` for development:

```bash
uv venv
uv pip install -e ".[dev]"
uv run pytest
uv run crowdsec-ops-mcp
```

Docker remains the recommended deployment path for the first version. Target environments should pull the published GHCR image; local image builds are for development and CI validation.

Image tags:

- `ghcr.io/frli4797/crowdsec-ops-mcp:0.1.1` for an exact release
- `ghcr.io/frli4797/crowdsec-ops-mcp:latest` for the latest release
- `ghcr.io/frli4797/crowdsec-ops-mcp:edge` or `:main` for the latest `main` build
- `ghcr.io/frli4797/crowdsec-ops-mcp:pr-123` for a same-repository PR preview image

Docker tags cannot contain `/` or `#`, so use `:edge`, `:main`, and `:pr-123`.

## Safety Checklist

- Prefer temporary allow entries over permanent allowlisting.
- Review every prepared write command before running it manually outside the MCP.
- Do not add bulk ban, bulk unban, or delete-all tools.
- Do not add direct access to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.
- Let agents orchestrate cross-system investigations through separate MCPs.

## Troubleshooting

If reads return no data:

- Confirm `CROWDSEC_LAPI_URL` points to the CrowdSec LAPI from inside the container network.
- Confirm `CROWDSEC_LAPI_KEY` is present in the container environment.
- Confirm CrowdSec has active decisions or recent alerts for the requested window.

If image pull fails with `401 Unauthorized` or `failed to resolve reference`:

- Confirm the target host is logged in to GHCR with `docker login ghcr.io`.
- Confirm the token has `read:packages`.
- Confirm the token identity has access to the private package or private repository.
- Alternatively, make the GHCR package public if unauthenticated pulls are acceptable.

If prepared write commands look wrong:

- Confirm `CSCLI_PATH` matches the command path operators expect to run.
- Confirm the returned potential command is valid for your CrowdSec deployment.
- Keep actual CrowdSec changes outside the MCP.
