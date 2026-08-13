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
# Optional, required for recent alert lists and scenario simulation writes:
CROWDSEC_LAPI_MACHINE_ID=replace-with-machine-id
CROWDSEC_LAPI_MACHINE_PASSWORD=replace-with-machine-password
# Required before any read-write tool can mutate CrowdSec state:
WRITE_OPERATIONS_ENABLED=false
```

3. Confirm the CrowdSec URL and network in `docker-compose.yml`:

```yaml
environment:
  CROWDSEC_LAPI_URL: http://crowdsec:8080
  CROWDSEC_LAPI_KEY: ${CROWDSEC_LAPI_KEY}
  CROWDSEC_LAPI_MACHINE_ID: ${CROWDSEC_LAPI_MACHINE_ID:-}
  CROWDSEC_LAPI_MACHINE_PASSWORD: ${CROWDSEC_LAPI_MACHINE_PASSWORD:-}
  WRITE_OPERATIONS_ENABLED: ${WRITE_OPERATIONS_ENABLED:-false}
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

Move a scenario into simulation:

```json
{
  "tool": "enable_scenario_simulation",
  "arguments": {
    "scenario": "local/snort-misc-attack-repeat",
    "reason": "new scenario should soak before remediation",
    "user_confirmation": "confirm scenario simulation enable local/snort-misc-attack-repeat"
  }
}
```

Scenario simulation responses include an `auth_context` object. These tools require `WRITE_OPERATIONS_ENABLED=true`, use LAPI machine auth, and execute a narrow audited API write for one scenario. Before calling them, agents must ask the user to approve the exact confirmation phrase: `confirm scenario simulation <action> <scenario>`.

The response includes the API method, redacted URL, status code, and appends attempted and applied records to the write audit log. The legacy `execute` flag is accepted for compatibility, but scenario simulation tools execute when called:

```json
{
  "tool": "disable_scenario_simulation",
  "arguments": {
    "scenario": "local/snort-misc-attack-repeat",
    "reason": "7d simulation period was clean and operator reviewed alerts",
    "user_confirmation": "confirm scenario simulation disable local/snort-misc-attack-repeat"
  }
}
```

IP write tools are still prepare-only. The MCP does not execute IP decision commands, even if a legacy `execute` flag is sent:

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

## Example Simulation Prompts And Approvals

Use this prompt shape when you want the agent to inspect context first and then ask for approval before changing simulation state:

```text
Review recent CrowdSec alerts for local/snort-misc-attack-repeat. If it is safe to keep testing, move it into simulation with reason "new scenario should soak before remediation". Before calling the write tool, ask me for the exact confirmation phrase.
```

The agent should stop and ask for exactly:

```text
confirm scenario simulation enable local/snort-misc-attack-repeat
```

Reply with only that phrase when you approve. The agent can then call:

```json
{
  "tool": "enable_scenario_simulation",
  "arguments": {
    "scenario": "local/snort-misc-attack-repeat",
    "reason": "new scenario should soak before remediation",
    "user_confirmation": "confirm scenario simulation enable local/snort-misc-attack-repeat"
  }
}
```

For promoting a reviewed scenario out of simulation, use:

```text
Move local/snort-misc-attack-repeat out of simulation with reason "7d simulation period was clean and operator reviewed alerts". Ask me for the exact confirmation phrase before calling the write tool.
```

Approve with:

```text
confirm scenario simulation disable local/snort-misc-attack-repeat
```

To discuss the change without allowing a write, say so explicitly:

```text
Review whether local/snort-misc-attack-repeat should leave simulation. Explain the evidence and recommended reason, but do not call any write tool.
```

Docker remains the recommended deployment path for the first version. Target environments should pull the published GHCR image.

Published image tags:

- `ghcr.io/frli4797/crowdsec-ops-mcp:0.2.1` for an exact release
- `ghcr.io/frli4797/crowdsec-ops-mcp:latest` for the latest release
- `ghcr.io/frli4797/crowdsec-ops-mcp:edge` or `:main` for the latest `main` build

## Safety Checklist

- Prefer temporary allow entries over permanent allowlisting.
- Keep `WRITE_OPERATIONS_ENABLED=false` unless you intentionally allow audited API write tools.
- Scenario simulation tools execute API writes when `WRITE_OPERATIONS_ENABLED=true`; review the scenario name and reason, then require the exact confirmation phrase before calling them.
- Review every prepared IP write command before running it manually outside the MCP.
- Prefer supported CrowdSec API-level access for new capabilities; do not design around remote `cscli` execution when a supported API path exists.
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
