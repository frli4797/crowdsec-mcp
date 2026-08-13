# Onboarding

This guide explains how to install, run, and use `crowdsec-ops-mcp`.

## What This MCP Does

`crowdsec-ops-mcp` exposes CrowdSec state and tightly scoped single-IP operator action proposals to an MCP client.

It only talks to CrowdSec. For broader investigations, use it alongside separate tools for logs, metrics, and dashboards.

## Prerequisites

- Docker and Docker Compose
- Network access from this container to CrowdSec LAPI
- A CrowdSec bouncer LAPI key for decision reads
- Optional CrowdSec machine credentials for alert list reads
- Optional: `CSCLI_PATH` configuration if you want generated command text to match a non-default operator command path

Do not mount the Docker socket into this container.

## Recommended Deployment

Run the MCP near CrowdSec, usually on the same Docker network as the CrowdSec service.

If the GHCR package is private or your deployment environment requires authenticated pulls, authenticate Docker to GHCR on the target host before pulling:

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
# Optional, required only for recent alert lists:
CROWDSEC_LAPI_MACHINE_ID=replace-with-machine-id
CROWDSEC_LAPI_MACHINE_PASSWORD=replace-with-machine-password
```

3. Confirm the CrowdSec URL and network in `docker-compose.yml`:

```yaml
environment:
  CROWDSEC_LAPI_URL: http://crowdsec:8080
  CROWDSEC_LAPI_KEY: ${CROWDSEC_LAPI_KEY}
  CROWDSEC_LAPI_MACHINE_ID: ${CROWDSEC_LAPI_MACHINE_ID:-}
  CROWDSEC_LAPI_MACHINE_PASSWORD: ${CROWDSEC_LAPI_MACHINE_PASSWORD:-}
networks:
  - security
```

## Alert List Machine Auth

CrowdSec bouncer API keys can read decisions, but they cannot read `/v1/alerts`. To let this MCP report recent alert counts and alert lists, create a dedicated CrowdSec machine on the CrowdSec host:

```bash
sudo cscli machines add crowdsec-ops-mcp
```

CrowdSec prints a generated password and writes machine credentials for local clients. Put the machine name and generated password in the MCP `.env`:

```bash
CROWDSEC_LAPI_MACHINE_ID=crowdsec-ops-mcp
CROWDSEC_LAPI_MACHINE_PASSWORD=replace-with-generated-password
```

If the machine is created from a different host with `cscli lapi register`, validate it on the LAPI server:

```bash
sudo cscli machines list
sudo cscli machines validate <machineName>
```

If these variables are not configured, tools that depend on alerts return an `alert_visibility.warning` explaining that alert lists require machine auth instead of silently implying there were zero alerts.

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

Prepare moving a scenario into simulation:

```json
{
  "tool": "enable_scenario_simulation",
  "arguments": {
    "scenario": "local/snort-misc-attack-repeat",
    "reason": "new scenario should soak before remediation"
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

Docker remains the recommended deployment path for the first version. Target environments should pull the published GHCR image.

Published image tags:

- `ghcr.io/frli4797/crowdsec-ops-mcp:0.2.1` for an exact release
- `ghcr.io/frli4797/crowdsec-ops-mcp:latest` for the latest release
- `ghcr.io/frli4797/crowdsec-ops-mcp:edge` or `:main` for the latest `main` build

## Safety Checklist

- Prefer temporary allow entries over permanent allowlisting.
- Review every prepared write command before running it manually outside the MCP.
- This MCP does not expose bulk ban, bulk unban, or delete-all tools.
- This MCP does not directly access VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.
- Use separate tools for logs, metrics, and dashboards when broader investigations need evidence outside CrowdSec.

## Troubleshooting

If reads return no data:

- Confirm `CROWDSEC_LAPI_URL` points to the CrowdSec LAPI from inside the container network.
- Confirm `CROWDSEC_LAPI_KEY` is present in the container environment.
- Confirm `CROWDSEC_LAPI_MACHINE_ID` and `CROWDSEC_LAPI_MACHINE_PASSWORD` are present when you need recent alert lists.
- Confirm CrowdSec has active decisions or recent alerts for the requested window.
- Do not expect `cscli` fallback reads; actual `cscli` reads are not supported by the MCP today.

If image pull fails with `401 Unauthorized` or `failed to resolve reference`:

- Confirm the target host is logged in to GHCR with `docker login ghcr.io`.
- Confirm the token has `read:packages`.
- Confirm the token identity has access to the private package or private repository.
- Alternatively, make the GHCR package public if unauthenticated pulls are acceptable.

If prepared write commands look wrong:

- Confirm `CSCLI_PATH` matches the command path operators expect to run manually outside the MCP.
- Confirm the returned potential command is valid for your CrowdSec deployment.
- Keep actual CrowdSec changes outside the MCP.
