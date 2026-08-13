# Decision Gap Report Example

Use `decision_gap_report` when you want to compare active CrowdSec decisions with recent alerts and find read-only attention points before considering any manual action.

## Basic Gap Report

```json
{
  "tool": "decision_gap_report",
  "arguments": {
    "window": "24h"
  }
}
```

The response includes:

- `summary` counts for active decisions, actionable recent alerts, and each finding type
- `alert_accounting`, which separates raw CrowdSec alert count, actionable alert count, and maintenance or otherwise non-actionable alert examples
- `alert_visibility`, which reports whether alert lists were available and which auth mode was used
- `findings.repeated_alerts_without_decision`
- `findings.active_decisions_without_recent_alerts`
- `findings.expiring_decisions_with_recent_alerts`
- `findings.noisy_scenarios`
- `findings.repeat_offenders_below_threshold`
- `recommendations`
- `mutation`, which remains `prepared_write_intents=false` and `executed=false`

## Tune Thresholds

```json
{
  "tool": "decision_gap_report",
  "arguments": {
    "window": "6h",
    "repeat_threshold": 5,
    "noisy_scenario_threshold": 20,
    "expiring_soon_hours": 12,
    "limit": 10
  }
}
```

Use stricter thresholds during noisy periods or broader windows. Thresholds apply to actionable alerts only; maintenance/update alerts remain visible in `alert_accounting` but do not drive findings. The tool only reports evidence and recommendations; it does not prepare or execute write actions.
