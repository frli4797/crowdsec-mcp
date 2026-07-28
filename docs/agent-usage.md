# Agent Usage

This guide contains prompt and investigation patterns for agents using `crowdsec-ops-mcp`.

## Core Practice

Use this MCP for CrowdSec evidence only. When a question needs logs, metrics, dashboards, IDS output, or reverse-proxy context, use separate tools for those sources and label the evidence clearly.

Good agent output should:

- name the time window
- separate facts from recommendations
- identify which source produced each fact
- state uncertainty when evidence is missing
- avoid claiming a CrowdSec action was executed
- return prepared commands only when explicitly requested or clearly warranted by the prompt

## Evidence Handling

For IP investigations, collect and report:

- active CrowdSec decisions
- recent CrowdSec alerts
- scenarios
- first and last alert timestamps
- country and ASN evidence when available
- current recommendation and rationale

For posture reviews, collect and report:

- active decision count
- recent alert count
- top source IPs
- top countries and ASNs
- top CrowdSec scenarios
- suspicious trends

For scenario proposals, include:

- observed pattern
- supporting counts
- proposed YAML
- expected noise
- risk and false-positive notes
- simulation period

## Prompt Patterns

Good prompts usually include:

- a specific IP or lookback window
- whether write proposals are wanted
- whether the answer should stay CrowdSec-only or use other tools
- the expected output, such as recommendation, potential command, or YAML proposal

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
