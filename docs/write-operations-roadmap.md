# Write Operations Roadmap

This note captures the current thinking around CrowdSec write operations so we can pause or resume the work without losing context.

## Current Position

The near-term priority may be to improve read-side tools and capabilities before enabling production write operations.

Read-side improvements are lower risk and likely more useful immediately:

- richer IP inspection
- clearer decision and alert summaries
- better top-offender and scenario evidence
- safer recommendations before any mutation is considered
- more useful output for agents that correlate CrowdSec with separate logs, metrics, and dashboard MCPs

## Existing Safe Write Foundation

The current safe write foundation prepares potential `cscli` commands and writes JSON Lines audit records.

This gives operators:

- a concrete command to review
- a record of write intent
- a safe path for local MCP testing
- a narrow single-IP surface for future execution

The audit log path is configured with:

```text
WRITE_AUDIT_LOG_PATH
```

For containerized Codex MCP usage, prefer a host-mounted audit directory so logs survive `docker compose run --rm`.

## Actual Execution Options

### Option 1: Execute With cscli

The proposed write execution path uses:

```bash
cscli decisions add --ip <ip> --type ban --reason <reason> --duration <duration>
cscli decisions delete --ip <ip>
```

This requires `cscli` to be available inside the MCP runtime environment.

If the MCP runs in Docker, installing the binary alone is not enough. `cscli` also needs CrowdSec machine credentials, normally mounted at:

```text
/etc/crowdsec/local_api_credentials.yaml
```

That file points `cscli` at LAPI and contains machine authentication, for example:

```yaml
url: http://crowdsec:8080
login: crowdsec-ops-mcp
password: <machine-password>
```

Important distinction:

- bouncer API keys are for reading decisions
- machine credentials are needed for creating and deleting decisions

If this path is used, keep the container setup explicit:

```yaml
environment:
  CSCLI_PATH: /usr/bin/cscli
  WRITE_AUDIT_LOG_PATH: /audit/write-audit.jsonl
volumes:
  - ./audit:/audit
  - ./local_api_credentials.yaml:/etc/crowdsec/local_api_credentials.yaml:ro
```

Pros:

- matches CrowdSec operator UX
- easy to show equivalent command to humans
- avoids implementing LAPI write details immediately

Cons:

- requires packaging or mounting `cscli`
- requires machine credential handling in the MCP runtime
- subprocess behavior must be carefully audited and tested

### Option 2: Execute Through LAPI

A future implementation could call LAPI directly with machine credentials.

Pros:

- structured HTTP behavior
- easier response handling and retries
- easier unit testing with HTTP mocks
- avoids installing `cscli` in the MCP image

Cons:

- requires exact CrowdSec write endpoint implementation
- still requires machine credentials
- less familiar to operators than `cscli`

## Safety Constraints For Any Write Path

Any future write execution should keep these constraints:

- single IP only
- no IP ranges
- no bulk ban or bulk unban
- no delete-all operation
- required reason for ban
- explicit `execute=true` for mutation
- prepared command returned even when executed
- audit entry before execution
- audit entry after execution with status, return code, stdout, and stderr or HTTP response details
- no Docker socket access
- no direct VictoriaMetrics, VictoriaLogs, Grafana, Snort, or reverse proxy access

## Recommended Next Step

Temporarily abandon production write execution and focus on read-side capabilities.

When write operations are revisited, decide first between:

1. packaging/mounting `cscli` plus machine credentials
2. implementing direct LAPI machine-auth writes

Until that decision is made, keep write execution PRs draft or experimental.
