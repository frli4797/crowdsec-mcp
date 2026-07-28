# Onboarding

This guide explains how to install, run, and use `crowdsec-ops-mcp`.

## What This MCP Does

`crowdsec-ops-mcp` exposes CrowdSec state and tightly scoped single-IP operator actions to an MCP client.

It only talks to CrowdSec. Agents are responsible for combining this MCP with separate logs, metrics, and dashboard MCPs when a broader investigation needs more context.

## Prerequisites

- Docker and Docker Compose
- Network access from this container to CrowdSec LAPI
- A CrowdSec LAPI key for read access
- Optional: `cscli` access or a wrapper if you want executed write actions

Do not mount the Docker socket into this container.

## Recommended Deployment

Run the MCP near CrowdSec, usually on the same Docker network as the CrowdSec service.

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

4. Start the container:

```bash
docker compose up --build -d
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

Dry-run a manual ban:

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

Execute only after reviewing the dry-run command:

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

## Local Development

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

Docker remains the recommended deployment path for the first version.

## Safety Checklist

- Keep `WRITE_EXECUTE_DEFAULT=false`.
- Prefer temporary allow entries over permanent allowlisting.
- Review every dry-run write command before setting `execute=true`.
- Do not add bulk ban, bulk unban, or delete-all tools.
- Do not add direct access to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.
- Let agents orchestrate cross-system investigations through separate MCPs.

## Troubleshooting

If reads return no data:

- Confirm `CROWDSEC_LAPI_URL` points to the CrowdSec LAPI from inside the container network.
- Confirm `CROWDSEC_LAPI_KEY` is present in the container environment.
- Confirm CrowdSec has active decisions or recent alerts for the requested window.

If write actions fail:

- Confirm the container has access to `cscli` or a configured `CSCLI_PATH`.
- Confirm the returned dry-run command is valid for your CrowdSec deployment.
- Keep write execution disabled until the command is known-good.

