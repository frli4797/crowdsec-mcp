from __future__ import annotations

from collections import Counter
from typing import Any

from .clients import CrowdSecClient
from .config import Config
from .models import CrowdSecAlert, Decision, Recommendation


class SecurityOps:
    def __init__(self, config: Config):
        self.config = config
        self.crowdsec = CrowdSecClient(config)

    async def inspect_ip(self, ip: str, window: str | None = None) -> dict[str, Any]:
        decisions = await self.crowdsec.decisions(ip)
        alerts = await self.crowdsec.alerts(ip, window)
        return {
            "ip": ip,
            "window": window or self.config.default_window,
            "active_decisions": [d.model_dump() for d in decisions],
            "crowdsec_alerts": [a.model_dump() for a in alerts],
            "summary": summarize_ip(decisions, alerts),
            "recommendation": recommend(decisions, alerts).model_dump(),
            "orchestration_hints": [
                "Use the logs MCP to fetch Snort, AppSec, NPM, and CrowdSec log events for this IP.",
                "Use the metrics MCP to check bouncer health and remediation counters.",
                "Use the Grafana MCP to link dashboards or annotate executed operator actions.",
            ],
        }

    async def security_summary(self, window: str | None = None) -> dict[str, Any]:
        decisions = await self.crowdsec.decisions()
        alerts = await self.crowdsec.alerts(window=window)
        return {
            "window": window or self.config.default_window,
            "active_decision_count": len(decisions),
            "recent_crowdsec_alert_count": len(alerts),
            "top_source_ips": top_source_ips(alerts),
            "top_countries": _top([x.country for x in decisions + alerts]),
            "top_asns": _top([x.as_name for x in decisions + alerts]),
            "top_crowdsec_scenarios": _top([x.scenario for x in alerts if x.scenario]),
            "decision_actions": _top([x.action for x in decisions]),
            "trends": suspicious_trends(decisions, alerts),
            "orchestration_hints": [
                "Ask the metrics MCP for CrowdSec bouncer and AppSec block health.",
                "Ask the logs MCP for Snort volume, top signatures, and related reverse proxy events.",
                "Ask the Grafana MCP for dashboard links when presenting the summary.",
            ],
        }

    async def top_offenders(self, window: str | None = None) -> dict[str, Any]:
        alerts = await self.crowdsec.alerts(window=window)
        return {"window": window or self.config.default_window, "source": "crowdsec", "top_source_ips": top_source_ips(alerts)}

    async def suggest_scenario(self, window: str | None = None) -> dict[str, Any]:
        alerts = await self.crowdsec.alerts(window=window)
        return scenario_suggestion(alerts, window or self.config.default_window)

    async def write_action(
        self,
        action: str,
        ip: str,
        duration: str | None,
        reason: str,
        execute: bool | None,
    ) -> dict[str, Any]:
        should_execute = self.config.write_execute_default if execute is None else execute
        result = await self.crowdsec.write_decision(action, ip, duration, reason, should_execute)
        if should_execute:
            result["audit_hint"] = "Use the Grafana MCP to create an annotation for this operator action."
        return result


def summarize_ip(decisions: list[Decision], alerts: list[CrowdSecAlert]) -> dict[str, Any]:
    return {
        "decision_actions": _top([d.action for d in decisions]),
        "countries": _top([x.country for x in decisions + alerts]),
        "asns": _top([x.as_name for x in decisions + alerts]),
        "crowdsec_scenarios": _top([x.scenario for x in alerts]),
        "first_timestamp": min([x for x in [a.created_at for a in alerts] if x], default=None),
        "last_timestamp": max([x for x in [a.created_at for a in alerts] if x], default=None),
    }


def recommend(decisions: list[Decision], alerts: list[CrowdSecAlert]) -> Recommendation:
    if decisions and alerts:
        return Recommendation(action="keep ban", rationale="There is an active decision and recent CrowdSec activity.", confidence="high")
    if decisions and not alerts:
        return Recommendation(action="monitor", rationale="The IP is currently remediated but has no recent CrowdSec alerts in the requested window.", confidence="medium")
    if len(alerts) >= 3 and not decisions:
        return Recommendation(action="manually ban", rationale="CrowdSec shows repeated recent alerts but no active decision.", confidence="medium")
    if alerts and not decisions:
        return Recommendation(action="monitor", rationale="CrowdSec has recent alerts, but no active decision is present.", confidence="medium")
    return Recommendation(action="ignore", rationale="No active CrowdSec decisions or recent CrowdSec alerts were found.", confidence="low")


def top_source_ips(alerts: list[CrowdSecAlert]) -> list[dict[str, Any]]:
    return _top([a.ip for a in alerts if a.ip], limit=20)


def suspicious_trends(decisions: list[Decision], alerts: list[CrowdSecAlert]) -> list[str]:
    trends: list[str] = []
    if len(decisions) == 0 and alerts:
        trends.append("Recent CrowdSec activity exists with no active CrowdSec decisions.")
    noisy_scenario = _top([a.scenario for a in alerts], limit=1)
    if noisy_scenario and noisy_scenario[0]["count"] >= 10:
        trends.append(f"Scenario is noisy: {noisy_scenario[0]['value']}")
    return trends


def scenario_suggestion(alerts: list[CrowdSecAlert], window: str) -> dict[str, Any]:
    scenarios = _top([x.scenario for x in alerts], limit=3)
    proposal = {
        "name": "local/crowdsec-repeat-offender",
        "simulation_period": "7d",
        "expected_noise": "medium" if scenarios else "unknown",
        "risk": "May over-remediate if the observed scenario is triggered by benign scanners, internal health checks, or misclassified traffic.",
        "evidence": {"top_crowdsec_scenarios": scenarios, "top_source_ips": top_source_ips(alerts)},
        "yaml": (
            "type: leaky\n"
            "name: local/crowdsec-repeat-offender\n"
            "description: Detect repeated CrowdSec alerts from the same source IP\n"
            "filter: evt.Meta.source_ip != ''\n"
            "groupby: evt.Meta.source_ip\n"
            "capacity: 5\n"
            "leakspeed: 10m\n"
            "blackhole: 1h\n"
            "labels:\n"
            "  remediation: true\n"
            "  service: crowdsec\n"
        ),
    }
    return {"window": window, "source_patterns_found": bool(scenarios), "proposal": proposal}


def _top(values: list[str | None], limit: int = 10) -> list[dict[str, Any]]:
    counter = Counter(v for v in values if v)
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]
