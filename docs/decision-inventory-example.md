# Decision Inventory Example

Use `decision_inventory` when you want to understand what CrowdSec is currently remediating and why, without inspecting one IP at a time.

## Basic Inventory

```json
{
  "tool": "decision_inventory",
  "arguments": {}
}
```

The response includes:

- `total_active_decisions`
- grouped counts under `grouped.actions`, `grouped.origins`, `grouped.scenarios`, `grouped.countries`, and `grouped.asns`
- `expiring_soon` decisions
- `stale_or_long_lived` decisions
- capped `representative_decisions`

## Focus On One Decision Type

```json
{
  "tool": "decision_inventory",
  "arguments": {
    "action": "ban",
    "limit": 10
  }
}
```

Use this to answer questions like "what is currently banned?" while keeping representative rows small enough for an MCP client response.

## Find Soon-To-Expire Decisions

```json
{
  "tool": "decision_inventory",
  "arguments": {
    "expiring_soon_hours": 6,
    "limit": 20
  }
}
```

Check `expiring_soon.count` first. If it is non-zero, review the returned rows and combine this MCP's CrowdSec-only evidence with separate logs or metrics before preparing any write action.

## Filter By Scenario Or Source Metadata

```json
{
  "tool": "decision_inventory",
  "arguments": {
    "scenario": "crowdsecurity/http-probing",
    "country": "SE",
    "asn": "Example ASN",
    "limit": 10
  }
}
```

Filters are exact, case-insensitive matches against active decision fields. Omit fields when you want the inventory grouped across all active decisions.

## Operator Prompt

```text
Use crowdsec-ops-mcp decision_inventory to summarize active CrowdSec bans. Show totals, top scenarios, top countries/ASNs, decisions expiring in the next 6h, and stale or long-lived decisions. Keep the answer CrowdSec-only and do not execute any write action.
```
