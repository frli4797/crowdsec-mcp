import json
from types import SimpleNamespace

import pytest

from crowdsec_ops_mcp.clients import CrowdSecClient, _alert_from_cscli, _decision_from_cscli, _decision_from_lapi
from crowdsec_ops_mcp.config import Config


def _config(audit_log_path):
    return Config(
        crowdsec_lapi_url=None,
        crowdsec_lapi_key=None,
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
    assert "without execution" in result["note"]

    entries = _audit_entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["status"] == "prepared"
    assert entries[0]["action"] == "ban"
    assert entries[0]["ip"] == "203.0.113.10"
    assert entries[0]["potential_cscli_command"] == result["potential_cscli_command"]
    assert "timestamp" in entries[0]


async def test_write_decision_execute_true_runs_unban_and_audits_request_and_result(tmp_path, monkeypatch):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))
    calls = []

    def fake_run(command, text, capture_output, check):
        calls.append(
            {
                "command": command,
                "text": text,
                "capture_output": capture_output,
                "check": check,
            }
        )
        return SimpleNamespace(returncode=0, stdout="deleted\n", stderr="")

    monkeypatch.setattr("crowdsec_ops_mcp.clients.subprocess.run", fake_run)

    result = await client.write_decision(
        action="unban",
        ip="203.0.113.10",
        duration="4h",
        reason="operator unban via MCP",
        execute=True,
    )

    assert calls == [
        {
            "command": ["cscli-test", "decisions", "delete", "--ip", "203.0.113.10"],
            "text": True,
            "capture_output": True,
            "check": False,
        }
    ]
    assert result["status"] == "executed"
    assert result["execute_requested"] is True
    assert result["executed"] is True
    assert result["duration"] is None
    assert result["potential_cscli_command"] == "cscli-test decisions delete --ip 203.0.113.10"
    assert result["returncode"] == 0
    assert result["stdout"] == "deleted\n"

    entries = _audit_entries(audit_log)
    assert [entry["status"] for entry in entries] == ["execute-requested", "executed"]
    assert entries[0]["execute_requested"] is True
    assert entries[0]["executed"] is False
    assert entries[0]["command"] == ["cscli-test", "decisions", "delete", "--ip", "203.0.113.10"]
    assert entries[1]["executed"] is True
    assert entries[1]["stdout"] == "deleted\n"


async def test_write_decision_execute_runs_fake_cscli_executable_for_ban(tmp_path, monkeypatch):
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
            cscli_path=str(fake_cscli),
            default_window="24h",
            write_audit_log_path=str(audit_log),
        )
    )
    monkeypatch.setenv("ARGV_LOG", str(argv_log))

    result = await client.write_decision(
        action="ban",
        ip="2001:db8::1",
        duration="30m",
        reason="local executable simulation",
        execute=True,
    )

    assert result["status"] == "executed"
    assert result["executed"] is True
    assert result["stdout"] == "fake cscli ok\n"
    assert argv_log.read_text(encoding="utf-8").splitlines() == [
        "decisions",
        "add",
        "--ip",
        "2001:db8::1",
        "--type",
        "ban",
        "--reason",
        "local executable simulation",
        "--duration",
        "30m",
    ]
    entries = _audit_entries(audit_log)
    assert [entry["status"] for entry in entries] == ["execute-requested", "executed"]


async def test_write_decision_execute_failure_is_reported_and_audited(tmp_path, monkeypatch):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    def fake_run(command, text, capture_output, check):
        return SimpleNamespace(returncode=1, stdout="", stderr="not found\n")

    monkeypatch.setattr("crowdsec_ops_mcp.clients.subprocess.run", fake_run)

    result = await client.write_decision(
        action="ban",
        ip="203.0.113.10",
        duration="1h",
        reason="test failure path",
        execute=True,
    )

    assert result["status"] == "failed"
    assert result["executed"] is False
    assert result["returncode"] == 1
    assert result["stderr"] == "not found\n"
    entries = _audit_entries(audit_log)
    assert [entry["status"] for entry in entries] == ["execute-requested", "failed"]


async def test_write_decision_execute_true_still_only_prepares_whitelist(tmp_path, monkeypatch):
    audit_log = tmp_path / "audit.jsonl"
    client = CrowdSecClient(_config(audit_log))

    def fake_run(command, text, capture_output, check):
        raise AssertionError("whitelist writes are prepare-only")

    monkeypatch.setattr("crowdsec_ops_mcp.clients.subprocess.run", fake_run)

    result = await client.write_decision(
        action="whitelist",
        ip="203.0.113.10",
        duration="1h",
        reason="temporary operator allowlist via MCP",
        execute=True,
    )

    assert result["status"] == "prepared"
    assert result["execute_requested"] is True
    assert result["executed"] is False
    assert "does not execute this CrowdSec write action yet" in result["note"]
    entries = _audit_entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["status"] == "prepared"


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
