import json
import logging
import pytest

from crowdsec_ops_mcp.clients import (
    CrowdSecClient,
    _alert_from_cscli,
    _alert_from_lapi,
    _decision_from_cscli,
    _decision_from_lapi,
    _redact_url,
)
from crowdsec_ops_mcp.config import Config


def _config(audit_log_path):
    return Config(
        crowdsec_lapi_url=None,
        crowdsec_lapi_key=None,
        crowdsec_lapi_machine_id=None,
        crowdsec_lapi_machine_password=None,
        crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
        write_operations_enabled=False,
        cscli_path="cscli-test",
        default_window="24h",
        write_audit_log_path=str(audit_log_path),
    )


def _lapi_config(audit_log_path):
    return Config(
        crowdsec_lapi_url="http://crowdsec:8080",
        crowdsec_lapi_key="lapi-secret",
        crowdsec_lapi_machine_id="mcp-machine",
        crowdsec_lapi_machine_password="machine-secret",
        crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
        write_operations_enabled=True,
        cscli_path="cscli-test",
        default_window="24h",
        write_audit_log_path=str(audit_log_path),
    )


def _audit_entries(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


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


def test_alert_from_lapi_nested_source_and_events():
    alert = _alert_from_lapi(
        {
            "source": {"value": "203.0.113.10", "cn": "SE", "asname": "Example ASN"},
            "scenario": "crowdsecurity/http-probing",
            "created_at": "2026-07-28T10:00:00Z",
            "events": [{"line": "one"}, {"line": "two"}],
        }
    )

    assert alert.ip == "203.0.113.10"
    assert alert.country == "SE"
    assert alert.as_name == "Example ASN"
    assert alert.events_count == 2


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


def test_redact_url_removes_embedded_credentials():
    assert _redact_url("http://user:secret@crowdsec:8080/api") == "http://crowdsec:8080/api"
    assert _redact_url("http://crowdsec:8080/api") == "http://crowdsec:8080/api"
    assert _redact_url(None) is None


def test_config_from_env_requires_explicit_write_enable(monkeypatch):
    monkeypatch.delenv("WRITE_OPERATIONS_ENABLED", raising=False)
    assert Config.from_env().write_operations_enabled is False

    monkeypatch.setenv("WRITE_OPERATIONS_ENABLED", "true")
    assert Config.from_env().write_operations_enabled is True


async def test_health_reports_cscli_mode_without_samples(tmp_path, monkeypatch, caplog):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))
    monkeypatch.setattr("crowdsec_ops_mcp.clients.shutil.which", lambda path: "/usr/bin/cscli-test")

    caplog.set_level(logging.INFO, logger="crowdsec_ops_mcp.clients")
    result = await client.health(["crowdsec_health", "inspect_ip"], include_sample_counts=False)

    assert result["backend_mode"] == "cscli"
    assert result["lapi"] == {
        "url_present": False,
        "api_key_present": False,
        "configured": False,
        "url": None,
        "reachable": None,
        "status_code": None,
        "error": None,
    }
    assert result["alert_auth"] == {
        "mode": "lapi_machine",
        "machine_id_present": False,
        "password_present": False,
        "configured": False,
        "authenticated": None,
        "error": None,
        "warning": "CrowdSec alert lists require CrowdSec LAPI plus machine auth.",
    }
    assert result["cscli"]["path"] == "cscli-test"
    assert result["cscli"]["available"] is True
    assert result["cscli"]["resolved_path"] == "/usr/bin/cscli-test"
    assert result["cscli"]["relevant"] is True
    assert result["default_window"] == "24h"
    assert result["write_audit_log_path"] == str(audit_log)
    assert result["exposed_tool_capabilities"] == ["crowdsec_health", "inspect_ip"]
    assert result["sample_counts"] is None
    assert "Checking CrowdSec backend health: mode=cscli include_sample_counts=False" in caplog.text
    assert "CrowdSec LAPI health skipped: url_present=False api_key_present=False" in caplog.text
    assert "CrowdSec cscli health checked: path=cscli-test available=True relevant=True" in caplog.text
    assert "CrowdSec backend health checked: mode=cscli lapi_configured=False lapi_reachable=None cscli_available=True" in caplog.text


async def test_health_sample_counts_are_optional_and_error_tolerant(tmp_path, monkeypatch, caplog):
    client = CrowdSecClient(_config(tmp_path / "audit.jsonl"))
    monkeypatch.setattr("crowdsec_ops_mcp.clients.shutil.which", lambda path: None)

    caplog.set_level(logging.INFO, logger="crowdsec_ops_mcp.clients")
    result = await client.health(["crowdsec_health"], include_sample_counts=True)

    assert result["cscli"]["available"] is False
    assert result["sample_counts"]["window"] == "24h"
    assert result["sample_counts"]["decisions"]["count"] is None
    assert result["sample_counts"]["decisions"]["error"] == "FileNotFoundError"
    assert result["sample_counts"]["alerts"]["count"] == 0
    assert result["sample_counts"]["alerts"]["error"] is None
    assert "CrowdSec health decision sample count failed: error=FileNotFoundError" in caplog.text
    assert "CrowdSec health sample counts checked: decisions=None alerts=0" in caplog.text


async def test_health_lapi_failure_logs_sanitized_url(tmp_path, respx_mock, caplog):
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url="http://machine:secret@crowdsec:8080",
            crowdsec_lapi_key="lapi-secret",
            crowdsec_lapi_machine_id=None,
            crowdsec_lapi_machine_password=None,
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path="cscli-test",
            default_window="24h",
            write_audit_log_path=str(tmp_path / "audit.jsonl"),
        )
    )
    respx_mock.get("http://crowdsec:8080/v1/decisions").respond(503, json={"message": "unavailable"})

    caplog.set_level(logging.INFO, logger="crowdsec_ops_mcp.clients")
    result = await client.health(["crowdsec_health"], include_sample_counts=False)

    assert result["lapi"]["url"] == "http://crowdsec:8080"
    assert result["lapi"]["reachable"] is False
    assert "CrowdSec LAPI health check failed: url=http://crowdsec:8080 error=HTTPStatusError" in caplog.text
    assert "machine:secret" not in caplog.text
    assert "lapi-secret" not in caplog.text


async def test_lapi_alerts_warn_when_machine_auth_missing(tmp_path, respx_mock, caplog):
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url="http://crowdsec:8080",
            crowdsec_lapi_key="bouncer-secret",
            crowdsec_lapi_machine_id=None,
            crowdsec_lapi_machine_password=None,
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path="cscli-test",
            default_window="24h",
            write_audit_log_path=str(tmp_path / "audit.jsonl"),
        )
    )

    caplog.set_level(logging.WARNING, logger="crowdsec_ops_mcp.clients")
    result = await client.alerts_with_status(window="24h")

    assert result["alerts"] == []
    assert result["status"]["available"] is False
    assert result["status"]["source"] == "lapi"
    assert result["status"]["auth_mode"] == "machine"
    assert "CROWDSEC_LAPI_MACHINE_ID" in result["status"]["warning"]
    assert not respx_mock.calls
    assert "LAPI machine auth is not configured" in caplog.text


async def test_lapi_decisions_treats_null_response_as_empty_list(tmp_path, respx_mock):
    client = CrowdSecClient(_lapi_config(tmp_path / "audit.jsonl"))
    respx_mock.get("http://crowdsec:8080/v1/decisions").respond(200, json=None)

    assert await client.decisions("203.0.113.10") == []


async def test_lapi_alerts_use_machine_auth(tmp_path, respx_mock):
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url="http://crowdsec:8080",
            crowdsec_lapi_key="bouncer-secret",
            crowdsec_lapi_machine_id="mcp-machine",
            crowdsec_lapi_machine_password="machine-secret",
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path="cscli-test",
            default_window="24h",
            write_audit_log_path=str(tmp_path / "audit.jsonl"),
        )
    )
    respx_mock.post("http://crowdsec:8080/v1/watchers/login").respond(200, json={"token": "jwt-token"})
    respx_mock.get("http://crowdsec:8080/v1/alerts").respond(
        200,
        json={
            "alerts": [
                {
                    "source": {"value": "203.0.113.10"},
                    "scenario": "crowdsecurity/http-probing",
                    "created_at": "2026-07-28T10:00:00Z",
                },
                {
                    "source": {"value": "198.51.100.3"},
                    "scenario": "crowdsecurity/http-crawl-non_statics",
                    "created_at": "2026-07-28T10:01:00Z",
                },
                {"scenario": "update : +15000/-0 IPs"},
            ]
        },
    )

    result = await client.alerts_with_status(ip="203.0.113.10", window="24h")

    assert result["status"]["available"] is True
    assert result["status"]["source"] == "lapi"
    assert result["status"]["auth_mode"] == "machine"
    assert [alert.ip for alert in result["alerts"]] == ["203.0.113.10"]
    alerts_request = respx_mock.calls.last.request
    assert alerts_request.headers["Authorization"] == "Bearer jwt-token"
    assert alerts_request.url.params["since"] == "24h"
    assert alerts_request.url.params["ip"] == "203.0.113.10"


async def test_cscli_alerts_filters_by_ip_client_side(tmp_path, monkeypatch):
    async def fake_run_json(args):
        assert "--ip" in args
        return [
            {"source": {"ip": "203.0.113.10"}, "scenario": "crowdsecurity/http-probing"},
            {"source": {"ip": "198.51.100.3"}, "scenario": "crowdsecurity/http-crawl-non_statics"},
            {"scenario": "update : +15000/-0 IPs"},
        ]

    client = CrowdSecClient(_config(tmp_path / "audit.jsonl"))
    monkeypatch.setattr("crowdsec_ops_mcp.clients._run_json", fake_run_json)

    alerts = await client.alerts("203.0.113.10", "24h")

    assert [alert.ip for alert in alerts] == ["203.0.113.10"]


async def test_write_decision_prepares_ban_command_and_audits(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    result = await client.write_decision(
        action="ban",
        ip="203.0.113.10",
        duration="4h",
        reason="confirmed repeated exploit attempts",
        execute=False,
    )

    assert result["status"] == "prepared"
    assert result["execute_requested"] is False
    assert result["executed"] is False
    assert result["command"] == [
        "cscli-test",
        "decisions",
        "add",
        "--ip",
        "203.0.113.10",
        "--type",
        "ban",
        "--reason",
        "confirmed repeated exploit attempts",
        "--duration",
        "4h",
    ]
    assert (
        result["potential_cscli_command"]
        == "cscli-test decisions add --ip 203.0.113.10 --type ban --reason 'confirmed repeated exploit attempts' --duration 4h"
    )
    assert "does not execute" in result["note"]

    entries = _audit_entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["status"] == "prepared"
    assert entries[0]["action"] == "ban"
    assert entries[0]["ip"] == "203.0.113.10"
    assert entries[0]["potential_cscli_command"] == result["potential_cscli_command"]
    assert "timestamp" in entries[0]


async def test_write_decision_execute_true_still_only_prepares_unban_and_audits(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    result = await client.write_decision(
        action="unban",
        ip="203.0.113.10",
        duration="4h",
        reason="operator unban via MCP",
        execute=True,
    )

    assert result["status"] == "prepared"
    assert result["execute_requested"] is True
    assert result["executed"] is False
    assert result["duration"] is None
    assert result["potential_cscli_command"] == "cscli-test decisions delete --ip 203.0.113.10"

    entries = _audit_entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["execute_requested"] is True
    assert entries[0]["executed"] is False
    assert entries[0]["command"] == ["cscli-test", "decisions", "delete", "--ip", "203.0.113.10"]


async def test_write_decision_does_not_run_fake_cscli_executable_even_when_execute_requested(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    argv_log = tmp_path / "argv.txt"
    fake_cscli = tmp_path / "cscli"
    fake_cscli.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$ARGV_LOG\"\n"
        "printf 'fake cscli ok\\n'\n",
        encoding="utf-8",
    )
    fake_cscli.chmod(0o755)
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url=None,
            crowdsec_lapi_key=None,
            crowdsec_lapi_machine_id=None,
            crowdsec_lapi_machine_password=None,
            crowdsec_lapi_simulation_path_template="/v1/scenarios/{scenario}/simulation",
            write_operations_enabled=False,
            cscli_path=str(fake_cscli),
            default_window="24h",
            write_audit_log_path=str(audit_log),
        )
    )

    result = await client.write_decision(
        action="ban",
        ip="2001:db8::1",
        duration="30m",
        reason="local executable simulation",
        execute=True,
    )

    assert result["status"] == "prepared"
    assert result["executed"] is False
    assert not argv_log.exists()
    entries = _audit_entries(audit_log)
    assert [entry["status"] for entry in entries] == ["prepared"]


async def test_write_decision_rejects_invalid_ip_before_audit(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    with pytest.raises(ValueError, match="Invalid IP address"):
        await client.write_decision(
            action="ban",
            ip="not-an-ip",
            duration="1h",
            reason="invalid input",
            execute=True,
        )

    assert not audit_log.exists()


async def test_write_scenario_simulation_enables_through_machine_auth_api_and_audits(tmp_path, respx_mock):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_lapi_config(audit_log))
    respx_mock.post("http://crowdsec:8080/v1/watchers/login").respond(200, json={"token": "machine-token"})
    simulation_route = respx_mock.post(
        "http://crowdsec:8080/v1/scenarios/local%2Fsnort-misc-attack-repeat/simulation"
    ).respond(200, json={"scenario": "local/snort-misc-attack-repeat", "simulation": True})

    result = await client.write_scenario_simulation(
        action="enable",
        scenario="local/snort-misc-attack-repeat",
        reason="new scenario should soak before remediation",
        user_confirmation="confirm scenario simulation enable local/snort-misc-attack-repeat",
        execute=False,
    )

    assert result["intent_type"] == "scenario_simulation"
    assert result["status"] == "applied"
    assert result["execute_requested"] is False
    assert result["executed"] is True
    assert result["method"] == "POST"
    assert result["url"] == "http://crowdsec:8080/v1/scenarios/local%2Fsnort-misc-attack-repeat/simulation"
    assert result["scenario"] == "local/snort-misc-attack-repeat"
    assert result["reason"] == "new scenario should soak before remediation"
    assert result["auth_context"] == {
        "lapi_machine_auth_configured": True,
        "auth_mode": "lapi_machine",
        "note": "CrowdSec scenario simulation is changed through the CrowdSec API with machine auth.",
    }
    assert result["status_code"] == 200
    assert result["response"] == {"scenario": "local/snort-misc-attack-repeat", "simulation": True}
    assert simulation_route.called
    assert simulation_route.calls[0].request.headers["authorization"] == "Bearer machine-token"
    assert json.loads(simulation_route.calls[0].request.content) == {
        "scenario": "local/snort-misc-attack-repeat",
        "reason": "new scenario should soak before remediation",
        "simulation": True,
        "user_confirmation": "confirm scenario simulation enable local/snort-misc-attack-repeat",
    }

    entries = _audit_entries(audit_log)
    assert len(entries) == 2
    assert entries[0]["intent_type"] == "scenario_simulation"
    assert entries[0]["action"] == "enable"
    assert entries[0]["status"] == "attempted"
    assert entries[0]["executed"] is None
    assert entries[1]["status"] == "applied"
    assert entries[1]["executed"] is True
    assert "timestamp" in entries[0]


async def test_write_scenario_simulation_disables_through_machine_auth_api(tmp_path, respx_mock):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_lapi_config(audit_log))
    respx_mock.post("http://crowdsec:8080/v1/watchers/login").respond(200, json={"token": "machine-token"})
    simulation_route = respx_mock.delete(
        "http://crowdsec:8080/v1/scenarios/crowdsecurity%2Fhttp-probing/simulation"
    ).respond(204)

    result = await client.write_scenario_simulation(
        action="disable",
        scenario="crowdsecurity/http-probing",
        reason="simulation period was clean",
        user_confirmation="confirm scenario simulation disable crowdsecurity/http-probing",
        execute=True,
    )

    assert result["status"] == "applied"
    assert result["execute_requested"] is True
    assert result["executed"] is True
    assert result["auth_context"]["lapi_machine_auth_configured"] is True
    assert result["auth_context"]["auth_mode"] == "lapi_machine"
    assert result["method"] == "DELETE"
    assert result["status_code"] == 204
    assert result["response"] is None
    assert simulation_route.called
    entries = _audit_entries(audit_log)
    assert entries[-1]["executed"] is True
    assert entries[0]["auth_context"]["lapi_machine_auth_configured"] is True


async def test_write_scenario_simulation_requires_machine_auth_before_audit(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    config = _config(audit_log)
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url=config.crowdsec_lapi_url,
            crowdsec_lapi_key=config.crowdsec_lapi_key,
            crowdsec_lapi_machine_id=config.crowdsec_lapi_machine_id,
            crowdsec_lapi_machine_password=config.crowdsec_lapi_machine_password,
            crowdsec_lapi_simulation_path_template=config.crowdsec_lapi_simulation_path_template,
            write_operations_enabled=True,
            cscli_path=config.cscli_path,
            default_window=config.default_window,
            write_audit_log_path=config.write_audit_log_path,
        )
    )

    with pytest.raises(RuntimeError, match="machine auth is required"):
        await client.write_scenario_simulation(
            action="enable",
            scenario="local/snort-misc-attack-repeat",
            reason="new scenario should soak before remediation",
            user_confirmation="confirm scenario simulation enable local/snort-misc-attack-repeat",
            execute=True,
        )

    assert not audit_log.exists()


async def test_write_scenario_simulation_requires_write_enable_before_audit(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    config = _lapi_config(audit_log)
    client = CrowdSecClient(
        Config(
            crowdsec_lapi_url=config.crowdsec_lapi_url,
            crowdsec_lapi_key=config.crowdsec_lapi_key,
            crowdsec_lapi_machine_id=config.crowdsec_lapi_machine_id,
            crowdsec_lapi_machine_password=config.crowdsec_lapi_machine_password,
            crowdsec_lapi_simulation_path_template=config.crowdsec_lapi_simulation_path_template,
            write_operations_enabled=False,
            cscli_path=config.cscli_path,
            default_window=config.default_window,
            write_audit_log_path=config.write_audit_log_path,
        )
    )

    with pytest.raises(RuntimeError, match="WRITE_OPERATIONS_ENABLED=true"):
        await client.write_scenario_simulation(
            action="enable",
            scenario="local/snort-misc-attack-repeat",
            reason="new scenario should soak before remediation",
            user_confirmation="confirm scenario simulation enable local/snort-misc-attack-repeat",
            execute=True,
        )

    assert not audit_log.exists()


async def test_write_scenario_simulation_requires_exact_user_confirmation_before_audit(tmp_path, respx_mock):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_lapi_config(audit_log))

    with pytest.raises(RuntimeError, match="requires exact user_confirmation"):
        await client.write_scenario_simulation(
            action="enable",
            scenario="local/snort-misc-attack-repeat",
            reason="new scenario should soak before remediation",
            user_confirmation="yes please",
            execute=True,
        )

    assert not audit_log.exists()
    assert not respx_mock.calls


async def test_write_scenario_simulation_audits_failed_api_response(tmp_path, respx_mock):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_lapi_config(audit_log))
    respx_mock.post("http://crowdsec:8080/v1/watchers/login").respond(200, json={"token": "machine-token"})
    respx_mock.post("http://crowdsec:8080/v1/scenarios/local%2Fsnort-misc-attack-repeat/simulation").respond(
        404,
        json={"message": "not found"},
    )

    with pytest.raises(Exception, match="404"):
        await client.write_scenario_simulation(
            action="enable",
            scenario="local/snort-misc-attack-repeat",
            reason="new scenario should soak before remediation",
            user_confirmation="confirm scenario simulation enable local/snort-misc-attack-repeat",
            execute=True,
        )

    entries = _audit_entries(audit_log)
    assert len(entries) == 2
    assert entries[0]["status"] == "attempted"
    assert entries[1]["status"] == "failed"
    assert entries[1]["executed"] is False
    assert entries[1]["status_code"] == 404
    assert entries[1]["response"] == {"message": "not found"}
    assert entries[1]["error"] == "HTTPStatusError"


async def test_write_scenario_simulation_rejects_invalid_scenario_before_audit(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    with pytest.raises(ValueError, match="Invalid CrowdSec scenario name"):
        await client.write_scenario_simulation(
            action="enable",
            scenario="local/scenario with spaces",
            reason="invalid input",
            user_confirmation="confirm scenario simulation enable local/scenario with spaces",
            execute=False,
        )

    assert not audit_log.exists()
