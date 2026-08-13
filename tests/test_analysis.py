import logging
from datetime import UTC, datetime

from crowdsec_ops_mcp.analysis import (
    SecurityOps,
    decision_gap_report,
    decision_inventory,
    filter_actionable_alerts,
    is_actionable_alert,
    non_actionable_alert_examples,
    recommend,
    scenario_suggestion,
    summarize_ip,
    suspicious_trends,
    top_source_ips,
)
from crowdsec_ops_mcp.config import Config
from crowdsec_ops_mcp.models import CrowdSecAlert, Decision


def test_recommend_keep_ban_with_recent_crowdsec_activity():
    decision = Decision(ip="203.0.113.10", action="ban", scenario="crowdsecurity/http-probing")
    alert = CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing")

    result = recommend([decision], [alert])

    assert result.action == "keep ban"
    assert result.confidence == "high"


def test_recommend_manual_ban_for_repeated_alerts_without_decision():
    alerts = [CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing") for _ in range(3)]

    result = recommend([], alerts)

    assert result.action == "manually ban"


def test_top_source_ips_uses_crowdsec_alerts_only():
    alerts = [
        CrowdSecAlert(ip="203.0.113.10"),
        CrowdSecAlert(ip="198.51.100.3"),
        CrowdSecAlert(ip="203.0.113.10"),
    ]

    assert top_source_ips(alerts)[0] == {"value": "203.0.113.10", "count": 2}


def test_actionable_alert_filter_skips_update_and_missing_ip_alerts():
    actionable = CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing")
    update = CrowdSecAlert(scenario="update : +15000/-0 IPs", created_at="2026-08-13T18:05:08Z")
    no_ip = CrowdSecAlert(scenario="crowdsecurity/http-probing")

    assert is_actionable_alert(actionable) is True
    assert is_actionable_alert(update) is False
    assert is_actionable_alert(no_ip) is False
    assert filter_actionable_alerts([actionable, update, no_ip]) == [actionable]

    assert non_actionable_alert_examples([actionable, update, no_ip]) == [
        {
            "scenario": "update : +15000/-0 IPs",
            "message": None,
            "created_at": "2026-08-13T18:05:08Z",
            "reason": "maintenance_or_update_alert",
        },
        {
            "scenario": "crowdsecurity/http-probing",
            "message": None,
            "created_at": None,
            "reason": "missing_source_ip",
        },
    ]


async def test_security_summary_separates_raw_and_actionable_alert_counts(tmp_path):
    ops = SecurityOps(
        Config(
            crowdsec_lapi_url=None,
            crowdsec_lapi_key=None,
            crowdsec_lapi_machine_id=None,
            crowdsec_lapi_machine_password=None,
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path="cscli-test",
            default_window="24h",
            write_audit_log_path=str(tmp_path / "audit.jsonl"),
        )
    )

    class FakeCrowdSec:
        async def decisions(self):
            return [Decision(ip="203.0.113.10", action="ban")]

        async def alerts_with_status(self, window=None):
            return {
                "window": window or "24h",
                "status": {"available": True, "source": "lapi", "auth_mode": "machine", "warning": None, "error": None},
                "alerts": [
                    CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing"),
                    CrowdSecAlert(scenario="update : +15000/-0 IPs"),
                ],
            }

    ops.crowdsec = FakeCrowdSec()

    summary = await ops.security_summary("24h")

    assert summary["recent_crowdsec_alert_count"] == 2
    assert summary["recent_actionable_alert_count"] == 1
    assert summary["non_actionable_alert_count"] == 1
    assert summary["top_source_ips"] == [{"value": "203.0.113.10", "count": 1}]
    assert summary["top_crowdsec_scenarios"] == [{"value": "crowdsecurity/http-probing", "count": 1}]


def test_summarize_ip_extracts_crowdsec_dimensions_and_timestamps():
    summary = summarize_ip(
        [Decision(ip="203.0.113.10", action="ban", country="SE")],
        [CrowdSecAlert(ip="203.0.113.10", scenario="scan", created_at="2026-07-28T10:00:00Z")],
    )

    assert summary["countries"] == [{"value": "SE", "count": 1}]
    assert summary["crowdsec_scenarios"] == [{"value": "scan", "count": 1}]
    assert summary["last_timestamp"] == "2026-07-28T10:00:00Z"


def test_scenario_suggestion_generates_yaml_proposal():
    suggestion = scenario_suggestion([CrowdSecAlert(scenario="crowdsecurity/http-probing") for _ in range(3)], "24h")

    assert suggestion["source_patterns_found"] is True
    assert "local/crowdsec-repeat-offender" in suggestion["proposal"]["yaml"]


def test_decision_inventory_groups_and_filters_active_decisions():
    inventory = decision_inventory(
        [
            Decision(
                ip="203.0.113.10",
                action="ban",
                origin="cscli",
                scenario="crowdsecurity/http-probing",
                country="SE",
                as_name="Example ASN",
                until="2026-07-28T18:00:00Z",
            ),
            Decision(
                ip="198.51.100.3",
                action="captcha",
                origin="crowdsec",
                scenario="crowdsecurity/http-crawl-non_statics",
                country="US",
                as_name="Other ASN",
                until="2026-07-28T20:00:00Z",
            ),
            Decision(ip="203.0.113.11", action="ban", origin="cscli", country="SE", as_name="Example ASN"),
        ],
        action="ban",
        country="se",
        limit=10,
        now=datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
    )

    assert inventory["total_active_decisions"] == 2
    assert inventory["grouped"]["actions"] == [{"value": "ban", "count": 2}]
    assert inventory["grouped"]["origins"] == [{"value": "cscli", "count": 2}]
    assert inventory["grouped"]["countries"] == [{"value": "SE", "count": 2}]
    assert inventory["representative_decisions"][0]["ip"] == "203.0.113.10"


def test_decision_inventory_expiry_views_and_limit():
    inventory = decision_inventory(
        [
            Decision(ip="203.0.113.10", action="ban", until="2026-07-28T14:00:00Z"),
            Decision(ip="203.0.113.11", action="ban", until="2026-08-30T12:00:00Z"),
            Decision(ip="203.0.113.12", action="ban"),
        ],
        limit=1,
        expiring_soon_hours=3,
        long_lived_days=30,
        now=datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
    )

    assert inventory["expiring_soon"]["count"] == 1
    assert inventory["expiring_soon"]["decisions"] == [
        {
            "ip": "203.0.113.10",
            "scope": "Ip",
            "action": "ban",
            "reason": None,
            "scenario": None,
            "country": None,
            "as_name": None,
            "until": "2026-07-28T14:00:00Z",
            "origin": None,
        }
    ]
    assert inventory["stale_or_long_lived"]["count"] == 2
    assert len(inventory["stale_or_long_lived"]["decisions"]) == 1
    assert inventory["stale_or_long_lived"]["decisions"][0]["ip"] == "203.0.113.11"


def test_decision_gap_report_finds_attention_gaps_without_mutation():
    report = decision_gap_report(
        [
            Decision(ip="203.0.113.20", action="ban", until="2026-07-28T13:00:00Z"),
            Decision(ip="203.0.113.30", action="ban", until="2026-08-30T12:00:00Z"),
        ],
        [
            CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing", events_count=4),
            CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing", events_count=6),
            CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-crawl-non_statics", events_count=1),
            CrowdSecAlert(ip="203.0.113.20", scenario="crowdsecurity/http-probing"),
            CrowdSecAlert(ip="198.51.100.9", scenario="crowdsecurity/http-probing"),
            CrowdSecAlert(ip="198.51.100.9", scenario="crowdsecurity/http-probing"),
        ],
        window="24h",
        repeat_threshold=3,
        noisy_scenario_threshold=3,
        expiring_soon_hours=2,
        now=datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
    )

    assert report["summary"] == {
        "active_decision_count": 2,
        "recent_alert_count": 6,
        "repeated_alert_ips_without_decision": 1,
        "active_decisions_without_recent_alerts": 1,
        "expiring_decisions_with_recent_alerts": 1,
        "noisy_scenarios": 1,
        "repeat_offenders_below_threshold": 1,
    }
    assert report["findings"]["repeated_alerts_without_decision"] == [
        {
            "ip": "203.0.113.10",
            "alert_count": 3,
            "event_count": 11,
            "top_scenarios": [
                {"value": "crowdsecurity/http-probing", "count": 2},
                {"value": "crowdsecurity/http-crawl-non_statics", "count": 1},
            ],
        }
    ]
    assert report["findings"]["active_decisions_without_recent_alerts"][0]["ip"] == "203.0.113.30"
    assert report["findings"]["expiring_decisions_with_recent_alerts"][0]["ip"] == "203.0.113.20"
    assert report["findings"]["noisy_scenarios"] == [{"scenario": "crowdsecurity/http-probing", "alert_count": 5}]
    assert report["findings"]["repeat_offenders_below_threshold"][0]["ip"] == "198.51.100.9"
    assert report["mutation"] == {"prepared_write_intents": False, "executed": False}
    assert {item["action"] for item in report["recommendations"]} == {
        "review repeat offenders",
        "review expiring decisions",
        "review quiet active decisions",
        "review noisy scenarios",
    }


def test_decision_gap_report_returns_monitor_when_no_thresholds_match():
    report = decision_gap_report(
        [Decision(ip="203.0.113.10", action="ban")],
        [CrowdSecAlert(ip="203.0.113.10", scenario="crowdsecurity/http-probing")],
        window="24h",
        repeat_threshold=3,
        noisy_scenario_threshold=10,
        now=datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
    )

    assert report["summary"]["repeated_alert_ips_without_decision"] == 0
    assert report["recommendations"] == [
        {
            "action": "monitor",
            "rationale": "No decision gaps exceeded the configured thresholds.",
            "confidence": "low",
        }
    ]
    assert report["mutation"]["executed"] is False


def test_suspicious_trends_flags_decision_gap():
    trends = suspicious_trends([], [CrowdSecAlert(scenario="crowdsecurity/http-probing")])

    assert any("no active CrowdSec decisions" in trend for trend in trends)


async def test_crowdsec_health_logs_analysis_lifecycle(tmp_path, monkeypatch, caplog):
    ops = SecurityOps(
        Config(
            crowdsec_lapi_url=None,
            crowdsec_lapi_key=None,
            crowdsec_lapi_machine_id=None,
            crowdsec_lapi_machine_password=None,
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path="cscli-test",
            default_window="24h",
            write_audit_log_path=str(tmp_path / "audit.jsonl"),
        )
    )
    monkeypatch.setattr("crowdsec_ops_mcp.clients.shutil.which", lambda path: "/usr/bin/cscli-test")

    caplog.set_level(logging.INFO, logger="crowdsec_ops_mcp.analysis")
    result = await ops.crowdsec_health(["crowdsec_health", "inspect_ip"], include_sample_counts=False)

    assert result["backend_mode"] == "cscli"
    assert "Building CrowdSec health report: mode=cscli include_sample_counts=False" in caplog.text
    assert "Built CrowdSec health report: mode=cscli lapi_reachable=None cscli_available=True capabilities=2" in caplog.text
