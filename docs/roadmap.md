# Project Roadmap

This note captures the current project roadmap for `crowdsec-ops-mcp` so we can pause or resume work without losing context.

## Current Position

The near-term priority is to improve read-side tools and capabilities before enabling production write operations.

Read-side improvements are lower risk and likely more useful immediately:

- richer IP inspection
- clearer decision and alert summaries
- better top-offender and scenario evidence
- safer recommendations before any mutation is considered
- more useful output for agents that correlate CrowdSec with separate logs, metrics, and dashboard MCPs

The roadmap has three main avenues:

- read-side CrowdSec investigation tools
- safe write-intent and future write execution design
- shared reliability, output contracts, and operator ergonomics

## Read-Side Investigation Tools

These additions should stay CrowdSec-only and should not mutate CrowdSec state.

### 1. Harden Existing Reads

Status: partially implemented.

Continue hardening the existing `cscli` JSON execution path:

- ensure the subprocess helper imports and handles its runtime dependencies correctly
- test `decisions()` and `alerts()` against representative mocked `cscli` JSON output
- cover `cscli` failures, empty output, malformed JSON, and missing executable behavior
- keep logs on stderr so stdio transport remains valid

### 2. Add a CrowdSec Health Tool

Status: implemented as `crowdsec_health(include_sample_counts=false)`.

Add a read-only `crowdsec_health` tool that helps operators understand why results may be empty or incomplete.

Useful fields:

- backend mode: LAPI or `cscli`
- LAPI URL presence and reachability, without exposing secrets
- `cscli` path and availability when relevant
- default lookback window
- write audit log path
- exposed tool capabilities
- optional tiny sample counts for decisions and alerts

### 3. Add Decision Inventory Views

Add a `decision_inventory` tool for answering what is currently remediated and why.

Useful filters:

- action
- origin
- scenario
- country
- ASN
- IP

Useful output:

- total active decisions
- decisions grouped by action, origin, scenario, country, and ASN
- decisions expiring soon
- stale or long-lived decisions
- representative decision rows with a configurable limit

### 4. Add Alert Timeline Bucketing

Add an `alert_timeline` tool that groups recent alerts into time buckets.

Useful inputs:

- `window`
- `bucket`, such as `15m`, `1h`, or `1d`
- optional scenario, country, ASN, or IP filters

Useful output:

- alert count per bucket
- event count per bucket when `events_count` is available
- top scenarios per bucket
- top source IPs per bucket
- first and last alert timestamps

### 5. Add Decision Gap Analysis

Add a `decision_gap_report` tool that highlights places where the read-only evidence suggests operator attention.

Useful findings:

- repeated alerts with no active decision
- active decisions with no recent alerts
- noisy scenarios
- top repeat offenders below any current decision threshold
- decisions that may be expiring while alerts continue

This tool should return evidence and recommendations only. It should not prepare write intents unless the caller explicitly invokes an existing write-intent tool separately.

### 6. Improve IP Inspection

Extend `inspect_ip` with normalized fields that make agent and human review easier.

Useful fields:

- first seen and last seen timestamps
- total alert count and total event count
- unique scenarios
- active decision actions
- decision expiry timestamps
- country and ASN evidence
- clearer recommendation shape with action, rationale, confidence, and suggested follow-up

### 7. Make Scenario Suggestions Evidence-Driven

Improve `suggest_scenario` so generated proposals are derived from observed alert frequency and distribution rather than always emitting a generic repeat-offender scenario.

Useful output:

- evidence used for capacity, leakspeed, groupby, and blackhole choices
- expected noise level
- simulation period
- risks and known false-positive patterns
- reasons not to apply the proposal
- YAML proposal kept as a suggested artifact only

### 8. Add Read-Only Write-Intent Audit Introspection

Add a `recent_write_intents` tool that reads the JSON Lines audit log and returns recently prepared commands.

Useful safeguards:

- configurable limit
- newest-first ordering
- graceful handling when the audit log does not exist
- no execution or replay behavior
- no bulk action helper

### 9. Add Limits and Pagination

List-like tools should accept limits so MCP responses stay small during busy periods.

Useful controls:

- `limit`
- optional offset or cursor-style continuation
- deterministic sort order
- clear truncation metadata

### 10. Tighten Output Contracts

Move frequently returned dictionaries into explicit response models where practical.

Good candidates:

- health response
- IP inspection summary
- recommendation
- decision inventory response
- alert timeline response
- gap analysis findings

This should make downstream agent behavior more predictable and make tests easier to read.

## Write Operations Avenue

Write operations should remain a separate avenue from read-side investigation work. The current project position is to keep production mutation paused while read-only operator value matures.

### Existing Safe Write Foundation

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

### Future Execution Options

When write operations are revisited, decide first between:

1. packaging or mounting `cscli` plus machine credentials
2. implementing direct LAPI machine-auth writes

Until that decision is made, keep write execution PRs draft or experimental.

#### Option 1: Execute With cscli

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

#### Option 2: Execute Through LAPI

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

### Safety Constraints For Any Write Path

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

## Suggested Implementation Order

Recommended sequence:

1. continue hardening the existing `cscli` read path
2. extend or refine `crowdsec_health`
3. add `decision_gap_report`
4. add `alert_timeline`
5. improve `inspect_ip`
6. add `decision_inventory`
7. improve `suggest_scenario`
8. add `recent_write_intents`
9. add pagination and stricter response models as shared cleanup
10. revisit write execution only after the read-side tools are stronger
