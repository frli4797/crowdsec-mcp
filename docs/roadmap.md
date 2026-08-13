# Project Roadmap

This note captures the current project roadmap for `crowdsec-ops-mcp` so we can pause or resume work without losing context.

## Current Position

The server now has a useful read-side foundation:

- `crowdsec_health` explains backend mode, LAPI reachability, `cscli` path diagnostics, configured defaults, write-audit path, and exposed capabilities.
- `decision_inventory` summarizes active decisions with filters, grouped counts, expiry views, long-lived/stale views, and representative rows.
- LAPI-backed alert reads use optional CrowdSec machine auth and report an explicit warning when only bouncer decision auth is configured.
- write tools are prepare-only and audited; the legacy `execute` flag is accepted but does not mutate CrowdSec state.
- scenario simulation tools prepare audited commands to move one scenario into or out of simulation, without executing CrowdSec changes.

Supported runtime reads use CrowdSec LAPI. Decision reads use bouncer API-key auth; alert reads require machine auth. Actual `cscli` reads and `cscli` execution are not supported today. `cscli` appears in current behavior only as prepared command text returned for human review.

The near-term priority remains read-side depth and operator ergonomics before revisiting any production write execution.

The roadmap now has three main avenues:

- sharper CrowdSec investigation tools
- safe write-intent audit visibility and future write execution design
- shared reliability, pagination, output contracts, and agent ergonomics

## Read-Side Investigation Tools

These additions should stay CrowdSec-only and should not mutate CrowdSec state.

### 1. Harden Existing Reads

Status: partially implemented.

Implemented:

- LAPI-backed `decisions()` and machine-auth `alerts()` have representative tests.
- decision reads tolerate empty LAPI responses, and IP-specific alert reads are filtered defensively client-side.
- health reporting covers LAPI reachability and sample-count behavior.
- logging stays on stderr so stdio transport remains valid.

Remaining work:

- decide whether to remove dormant `cscli` read fallback code or promote it to a documented, tested feature later
- continue broadening sparse-field coverage as more real CrowdSec response variants are observed

### 2. Add a CrowdSec Health Tool

Status: implemented as `crowdsec_health(include_sample_counts=false)`.

The read-only `crowdsec_health` tool helps operators understand why results may be empty or incomplete.

Implemented fields:

- backend mode, currently expected to be LAPI for supported deployments
- LAPI URL presence and reachability, without exposing secrets
- alert machine-auth presence and authentication status, without exposing secrets
- `cscli` path/availability diagnostics as implementation detail only; this is not a supported read or execution mode
- default lookback window
- write audit log path
- exposed tool capabilities
- optional tiny sample counts for decisions and alerts

### 3. Add Decision Inventory Views

Status: implemented as `decision_inventory(...)`.

The `decision_inventory` tool answers what is currently remediated and why.

Implemented filters:

- action
- origin
- scenario
- country
- ASN
- IP

Implemented output:

- total active decisions
- decisions grouped by action, origin, scenario, country, and ASN
- decisions expiring soon
- stale or long-lived decisions
- representative decision rows with a configurable limit

### 4. Add Alert Timeline Bucketing

Status: not implemented.

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

Status: implemented as `decision_gap_report(...)`.

The `decision_gap_report` tool highlights places where the read-only evidence suggests operator attention.

Implemented findings:

- repeated alerts with no active decision
- active decisions with no recent alerts
- noisy scenarios
- top repeat offenders below any current decision threshold
- decisions that may be expiring while alerts continue

This tool returns evidence and recommendations only. It does not prepare write intents.

### 6. Improve IP Inspection

Status: partially implemented.

Extend `inspect_ip` with normalized fields that make agent and human review easier.

Already available:

- active decisions for the IP
- recent CrowdSec alerts for the IP
- summary fields for decision actions, countries, ASNs, scenarios, first timestamp, and last timestamp
- recommendation with action, rationale, and confidence

Remaining useful fields:

- total alert count and total event count
- unique scenarios
- decision expiry timestamps
- suggested follow-up
- clear indication when an IP-specific backend lookup fails but broader data is still available

### 7. Make Scenario Suggestions Evidence-Driven

Status: partially implemented; currently generic.

Improve `suggest_scenario` so generated proposals are derived from observed alert frequency and distribution rather than always emitting a generic repeat-offender scenario.

Useful output:

- evidence used for capacity, leakspeed, groupby, and blackhole choices
- expected noise level
- simulation period
- risks and known false-positive patterns
- reasons not to apply the proposal
- YAML proposal kept as a suggested artifact only

### 8. Add Read-Only Write-Intent Audit Introspection

Status: not implemented.

Add a `recent_write_intents` tool that reads the JSON Lines audit log and returns recently prepared commands.

Useful safeguards:

- configurable limit
- newest-first ordering
- graceful handling when the audit log does not exist
- no execution or replay behavior
- no bulk action helper

### 9. Add Limits and Pagination

Status: partially implemented.

Implemented:

- `decision_inventory` accepts `limit` and caps it to a safe maximum.

Remaining work:

List-like tools should accept limits so MCP responses stay small during busy periods.

Useful controls:

- `limit`
- optional offset or cursor-style continuation
- deterministic sort order
- clear truncation metadata

### 10. Tighten Output Contracts

Status: partially implemented.

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

The current safe write foundation prepares potential `cscli` command text and writes JSON Lines audit records. The MCP does not run those commands.

This gives operators:

- a concrete command to review
- a record of write intent
- a safe path for local MCP testing
- a narrow single-IP decision surface and single-scenario simulation surface for future execution review

The audit log path is configured with:

```text
WRITE_AUDIT_LOG_PATH
```

For containerized Codex MCP usage, prefer a host-mounted audit directory so logs survive `docker compose run --rm`.

### Scenario Simulation Intents

Status: implemented as `enable_scenario_simulation(...)` and `disable_scenario_simulation(...)`.

Scenario simulation moves are treated as prepared operator intents, not executed mutations. They generate:

```bash
cscli simulation enable <scenario>
cscli simulation disable <scenario>
```

The tools require one scenario name and a human-readable reason. They append to the same JSON Lines write-audit log as IP decision intents and return `executed=false`, including when a legacy `execute=true` flag is supplied. Responses include non-secret auth context that reports LAPI machine-auth availability while making clear that the prepared simulation command is a local `cscli` configuration operation.

This is useful for:

- putting newly installed or newly tuned scenarios into simulation first
- promoting a reviewed scenario out of simulation after a clean soak period
- rolling a noisy scenario back into simulation while preserving an audit trail

Remaining useful follow-up:

- expose recent scenario simulation intents through the future `recent_write_intents` read-only audit tool
- decide whether future decision execution should use `cscli` with machine credentials or direct LAPI machine-auth writes
- only consider scenario simulation execution through an explicit local `cscli` and configuration mount design, unless CrowdSec exposes a supported LAPI endpoint for simulation management later
- keep any future execution single-scenario only, with explicit reason and audit records before and after execution

### Future Execution Options

When decision write operations are revisited, decide first between:

1. packaging or mounting `cscli` plus machine credentials
2. implementing direct LAPI machine-auth writes

Until that decision is made, keep write execution PRs draft or experimental.

#### Option 1: Execute With cscli

Status: future option only; not supported today.

The proposed write execution path would use:

```bash
cscli decisions add --ip <ip> --type ban --reason <reason> --duration <duration>
cscli decisions delete --ip <ip>
```

This would require `cscli` to be available inside the MCP runtime environment.

If the MCP runs in Docker, installing the binary alone would not be enough. `cscli` also needs CrowdSec machine credentials, normally mounted at:

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
- scenario simulation is managed by `cscli` through local simulation configuration, not by the bouncer decision API

If this path is used in the future, keep the container setup explicit:

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

#### Option 2: Execute Decisions Through LAPI

A future implementation could call LAPI directly with machine credentials for decision writes.

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

- decision writes are single-IP only
- scenario simulation writes are single-scenario only
- no IP ranges
- no bulk ban or bulk unban
- no delete-all operation
- required reason for ban, allow, unban, and scenario simulation changes
- explicit `execute=true` for mutation
- prepared command returned even when executed
- audit entry before execution
- audit entry after execution with status, return code, stdout, and stderr or HTTP response details
- no Docker socket access
- no direct VictoriaMetrics, VictoriaLogs, Grafana, Snort, or reverse proxy access

## Suggested Implementation Order

Recommended sequence from the current state:

1. fix sparse IP lookup edge cases found in `decision_inventory(ip=...)`
2. add `alert_timeline`
3. improve `inspect_ip` with counts, event totals, expiry summaries, and suggested follow-up
4. make `suggest_scenario` evidence-driven instead of generic
5. add read-only `recent_write_intents`
6. add limits or pagination to list-like tools beyond `decision_inventory`
7. tighten high-value output contracts with explicit response models
8. decide whether dormant `cscli` read fallback code should be removed or promoted to supported functionality
9. revisit write execution only after the read-side tools and audit introspection are stronger
