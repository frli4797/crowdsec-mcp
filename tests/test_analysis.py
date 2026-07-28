from datetime import UTC, datetime

from crowdsec_ops_mcp.analysis import decision_inventory, recommend, scenario_suggestion, summarize_ip, suspicious_trends, top_source_ips
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


def test_suspicious_trends_flags_decision_gap():
    trends = suspicious_trends([], [CrowdSecAlert(scenario="crowdsecurity/http-probing")])

    assert any("no active CrowdSec decisions" in trend for trend in trends)
