from crowdsec_ops_mcp.analysis import recommend, scenario_suggestion, summarize_ip, suspicious_trends, top_source_ips
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


def test_suspicious_trends_flags_decision_gap():
    trends = suspicious_trends([], [CrowdSecAlert(scenario="crowdsecurity/http-probing")])

    assert any("no active CrowdSec decisions" in trend for trend in trends)
