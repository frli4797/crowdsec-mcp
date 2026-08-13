from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import logging
from typing import Any

from .clients import CrowdSecClient
from .config import Config
from .models import CrowdSecAlert, Decision, Recommendation

logger = logging.getLogger(__name__)


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
        }

    async def top_offenders(self, window: str | None = None) -> dict[str, Any]:
        alerts = await self.crowdsec.alerts(window=window)
        return {"window": window or self.config.default_window, "source": "crowdsec", "top_source_ips": top_source_ips(alerts)}

    async def decision_inventory(
        self,
        action: str | None = None,
        origin: str | None = None,
        scenario: str | None = None,
        country: str | None = None,
        asn: str | None = None,
        ip: str | None = None,
        limit: int = 20,
        expiring_soon_hours: int = 24,
        long_lived_days: int = 30,
    ) -> dict[str, Any]:
        decisions = await self.crowdsec.decisions(ip)
        return decision_inventory(
            decisions,
            action=action,
            origin=origin,
            scenario=scenario,
            country=country,
            asn=asn,
            ip=ip,
            limit=limit,
            expiring_soon_hours=expiring_soon_hours,
            long_lived_days=long_lived_days,
        )

    async def decision_gap_report(
        self,
        window: str | None = None,
        repeat_threshold: int = 3,
        noisy_scenario_threshold: int = 10,
        expiring_soon_hours: int = 24,
        limit: int = 20,
    ) -> dict[str, Any]:
        decisions = await self.crowdsec.decisions()
        alerts = await self.crowdsec.alerts(window=window)
        return decision_gap_report(
            decisions,
            alerts,
            window=window or self.config.default_window,
            repeat_threshold=repeat_threshold,
            noisy_scenario_threshold=noisy_scenario_threshold,
            expiring_soon_hours=expiring_soon_hours,
            limit=limit,
        )

    async def suggest_scenario(self, window: str | None = None) -> dict[str, Any]:
        alerts = await self.crowdsec.alerts(window=window)
        return scenario_suggestion(alerts, window or self.config.default_window)

    async def crowdsec_health(self, capabilities: list[str], include_sample_counts: bool = False) -> dict[str, Any]:
        logger.info(
            "Building CrowdSec health report: mode=%s include_sample_counts=%s",
            self.crowdsec.mode,
            include_sample_counts,
        )
        health = await self.crowdsec.health(capabilities, include_sample_counts)
        logger.info(
            "Built CrowdSec health report: mode=%s lapi_reachable=%s cscli_available=%s capabilities=%d",
            health["backend_mode"],
            health["lapi"]["reachable"],
            health["cscli"]["available"],
            len(capabilities),
        )
        return health

    async def write_action(
        self,
        action: str,
        ip: str,
        duration: str | None,
        reason: str,
        execute: bool | None,
    ) -> dict[str, Any]:
        return await self.crowdsec.write_decision(action, ip, duration, reason, bool(execute))

    async def scenario_simulation_action(
        self,
        action: str,
        scenario: str,
        reason: str,
        execute: bool | None,
    ) -> dict[str, Any]:
        return await self.crowdsec.write_scenario_simulation(action, scenario, reason, bool(execute))


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


def decision_inventory(
    decisions: list[Decision],
    *,
    action: str | None = None,
    origin: str | None = None,
    scenario: str | None = None,
    country: str | None = None,
    asn: str | None = None,
    ip: str | None = None,
    limit: int = 20,
    expiring_soon_hours: int = 24,
    long_lived_days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = _as_utc(now or datetime.now(UTC))
    filtered = [
        decision
        for decision in decisions
        if _matches(decision.action, action)
        and _matches(decision.origin, origin)
        and _matches(decision.scenario, scenario)
        and _matches(decision.country, country)
        and _matches(decision.as_name, asn)
        and _matches(decision.ip, ip)
    ]
    limit = max(0, min(limit, 100))
    expiring_soon_cutoff = now + timedelta(hours=max(expiring_soon_hours, 0))
    long_lived_cutoff = now + timedelta(days=max(long_lived_days, 0))

    expiring_soon = [
        decision
        for decision in filtered
        if (until := _parse_timestamp(decision.until)) is not None and now <= until <= expiring_soon_cutoff
    ]
    stale_or_long_lived = [
        decision
        for decision in filtered
        if decision.until is None or ((until := _parse_timestamp(decision.until)) is not None and until >= long_lived_cutoff)
    ]

    return {
        "filters": {
            "action": action,
            "origin": origin,
            "scenario": scenario,
            "country": country,
            "asn": asn,
            "ip": ip,
        },
        "total_active_decisions": len(filtered),
        "grouped": {
            "actions": _top([d.action for d in filtered]),
            "origins": _top([d.origin for d in filtered]),
            "scenarios": _top([d.scenario for d in filtered]),
            "countries": _top([d.country for d in filtered]),
            "asns": _top([d.as_name for d in filtered]),
        },
        "expiring_soon": {
            "within_hours": max(expiring_soon_hours, 0),
            "count": len(expiring_soon),
            "decisions": [_decision_row(d) for d in _sort_by_until(expiring_soon)[:limit]],
        },
        "stale_or_long_lived": {
            "long_lived_days": max(long_lived_days, 0),
            "count": len(stale_or_long_lived),
            "decisions": [_decision_row(d) for d in _sort_by_until(stale_or_long_lived)[:limit]],
        },
        "representative_decisions": [_decision_row(d) for d in _sort_by_until(filtered)[:limit]],
        "limit": limit,
    }


def decision_gap_report(
    decisions: list[Decision],
    alerts: list[CrowdSecAlert],
    *,
    window: str,
    repeat_threshold: int = 3,
    noisy_scenario_threshold: int = 10,
    expiring_soon_hours: int = 24,
    limit: int = 20,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = _as_utc(now or datetime.now(UTC))
    repeat_threshold = max(repeat_threshold, 1)
    noisy_scenario_threshold = max(noisy_scenario_threshold, 1)
    expiring_soon_hours = max(expiring_soon_hours, 0)
    limit = max(0, min(limit, 100))
    active_decision_ips = {d.ip for d in decisions if d.ip}
    alert_ips = {a.ip for a in alerts if a.ip}
    alert_counts_by_ip = Counter(a.ip for a in alerts if a.ip)
    event_counts_by_ip: Counter[str] = Counter()
    scenarios_by_ip: dict[str, Counter[str]] = {}
    for alert in alerts:
        if not alert.ip:
            continue
        event_counts_by_ip[alert.ip] += alert.events_count or 0
        if alert.scenario:
            scenarios_by_ip.setdefault(alert.ip, Counter())[alert.scenario] += 1

    repeated_without_decision = [
        _ip_gap_row(ip, alert_counts_by_ip[ip], event_counts_by_ip[ip], scenarios_by_ip.get(ip))
        for ip in alert_counts_by_ip
        if ip not in active_decision_ips and alert_counts_by_ip[ip] >= repeat_threshold
    ]
    below_threshold_without_decision = [
        _ip_gap_row(ip, alert_counts_by_ip[ip], event_counts_by_ip[ip], scenarios_by_ip.get(ip))
        for ip in alert_counts_by_ip
        if ip not in active_decision_ips and 1 < alert_counts_by_ip[ip] < repeat_threshold
    ]
    active_without_recent_alerts = [d for d in decisions if d.ip not in alert_ips]
    expiring_cutoff = now + timedelta(hours=expiring_soon_hours)
    expiring_with_recent_alerts = [
        d
        for d in decisions
        if d.ip in alert_ips and (until := _parse_timestamp(d.until)) is not None and now <= until <= expiring_cutoff
    ]
    noisy_scenarios = [
        {"scenario": row["value"], "alert_count": row["count"]}
        for row in _top([a.scenario for a in alerts if a.scenario], limit=100)
        if row["count"] >= noisy_scenario_threshold
    ]

    repeated_without_decision = sorted(repeated_without_decision, key=_ip_gap_sort_key)[:limit]
    below_threshold_without_decision = sorted(below_threshold_without_decision, key=_ip_gap_sort_key)[:limit]
    active_without_recent_alerts = _sort_by_until(active_without_recent_alerts)[:limit]
    expiring_with_recent_alerts = _sort_by_until(expiring_with_recent_alerts)[:limit]
    noisy_scenarios = noisy_scenarios[:limit]

    recommendations: list[dict[str, Any]] = []
    if repeated_without_decision:
        recommendations.append(
            {
                "action": "review repeat offenders",
                "rationale": "Recent repeated CrowdSec alerts exist for IPs without active decisions.",
                "confidence": "medium",
            }
        )
    if expiring_with_recent_alerts:
        recommendations.append(
            {
                "action": "review expiring decisions",
                "rationale": "Some active decisions are expiring soon while recent alerts continue.",
                "confidence": "medium",
            }
        )
    if active_without_recent_alerts:
        recommendations.append(
            {
                "action": "review quiet active decisions",
                "rationale": "Some active decisions have no recent CrowdSec alerts in the requested window.",
                "confidence": "low",
            }
        )
    if noisy_scenarios:
        recommendations.append(
            {
                "action": "review noisy scenarios",
                "rationale": "One or more CrowdSec scenarios are generating high recent alert volume.",
                "confidence": "medium",
            }
        )
    if not recommendations:
        recommendations.append(
            {
                "action": "monitor",
                "rationale": "No decision gaps exceeded the configured thresholds.",
                "confidence": "low",
            }
        )

    return {
        "window": window,
        "thresholds": {
            "repeat_threshold": repeat_threshold,
            "noisy_scenario_threshold": noisy_scenario_threshold,
            "expiring_soon_hours": expiring_soon_hours,
        },
        "summary": {
            "active_decision_count": len(decisions),
            "recent_alert_count": len(alerts),
            "repeated_alert_ips_without_decision": len(repeated_without_decision),
            "active_decisions_without_recent_alerts": len(active_without_recent_alerts),
            "expiring_decisions_with_recent_alerts": len(expiring_with_recent_alerts),
            "noisy_scenarios": len(noisy_scenarios),
            "repeat_offenders_below_threshold": len(below_threshold_without_decision),
        },
        "findings": {
            "repeated_alerts_without_decision": repeated_without_decision,
            "active_decisions_without_recent_alerts": [_decision_row(d) for d in active_without_recent_alerts],
            "expiring_decisions_with_recent_alerts": [_decision_row(d) for d in expiring_with_recent_alerts],
            "noisy_scenarios": noisy_scenarios,
            "repeat_offenders_below_threshold": below_threshold_without_decision,
        },
        "recommendations": recommendations,
        "limit": limit,
        "mutation": {"prepared_write_intents": False, "executed": False},
    }


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


def _matches(value: str | None, expected: str | None) -> bool:
    if expected is None:
        return True
    return (value or "").casefold() == expected.casefold()


def _decision_row(decision: Decision) -> dict[str, Any]:
    return decision.model_dump()


def _ip_gap_row(ip: str, alert_count: int, event_count: int, scenarios: Counter[str] | None) -> dict[str, Any]:
    return {
        "ip": ip,
        "alert_count": alert_count,
        "event_count": event_count,
        "top_scenarios": [{"value": value, "count": count} for value, count in (scenarios or Counter()).most_common(5)],
    }


def _ip_gap_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    return -row["alert_count"], -row["event_count"], row["ip"]


def _sort_by_until(decisions: list[Decision]) -> list[Decision]:
    def key(decision: Decision) -> tuple[bool, datetime, str]:
        until = _parse_timestamp(decision.until)
        return until is None, until or datetime.max.replace(tzinfo=UTC), decision.ip

    return sorted(decisions, key=key)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return _as_utc(datetime.fromisoformat(normalized))
    except ValueError:
        return None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
