from crowdsec_ops_mcp.clients import _alert_from_cscli, _decision_from_cscli, _decision_from_lapi


def test_decision_from_cscli_common_fields():
    decision = _decision_from_cscli(
        {
            "value": "203.0.113.10",
            "type": "ban",
            "reason": "crowdsecurity/http-probing",
            "country": "SE",
            "as_name": "Example ASN",
        }
    )

    assert decision.ip == "203.0.113.10"
    assert decision.action == "ban"
    assert decision.country == "SE"


def test_alert_from_cscli_nested_source():
    alert = _alert_from_cscli(
        {
            "source": {"ip": "203.0.113.10", "country": "SE", "as_name": "Example ASN"},
            "scenario": "crowdsecurity/http-probing",
            "created_at": "2026-07-28T10:00:00Z",
            "events_count": 4,
        }
    )

    assert alert.ip == "203.0.113.10"
    assert alert.scenario == "crowdsecurity/http-probing"
    assert alert.events_count == 4


def test_decision_from_lapi_common_fields():
    decision = _decision_from_lapi(
        {
            "value": "203.0.113.10",
            "type": "ban",
            "reason": "manual test",
            "origin": "cscli",
            "until": "2026-07-28T12:00:00Z",
        }
    )

    assert decision.ip == "203.0.113.10"
    assert decision.action == "ban"
    assert decision.origin == "cscli"
