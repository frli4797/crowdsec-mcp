from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any

import httpx

from .config import Config
from .models import CrowdSecAlert, Decision


class CrowdSecClient:
    def __init__(self, config: Config):
        self.config = config

    async def decisions(self, ip: str | None = None) -> list[Decision]:
        if self.config.crowdsec_lapi_url and self.config.crowdsec_lapi_key:
            params = {"ip": ip} if ip else {}
            async with httpx.AsyncClient(timeout=20) as client:
                res = await client.get(
                    f"{self.config.crowdsec_lapi_url.rstrip('/')}/v1/decisions",
                    params=params,
                    headers={"X-Api-Key": self.config.crowdsec_lapi_key},
                )
                res.raise_for_status()
                return [_decision_from_lapi(item) for item in res.json()]
        args = [self.config.cscli_path, "decisions", "list", "-o", "json"]
        if ip:
            args.extend(["--ip", ip])
        return [_decision_from_cscli(item) for item in await _run_json(args)]

    async def alerts(self, ip: str | None = None, window: str | None = None) -> list[CrowdSecAlert]:
        args = [self.config.cscli_path, "alerts", "list", "-o", "json", "--since", window or self.config.default_window]
        if ip:
            args.extend(["--ip", ip])
        try:
            rows = await _run_json(args)
        except FileNotFoundError:
            return []
        return [_alert_from_cscli(item) for item in rows]

    async def write_decision(
        self,
        action: str,
        ip: str,
        duration: str | None,
        reason: str,
        execute: bool,
    ) -> dict[str, Any]:
        command = [self.config.cscli_path, "decisions", "add", "--ip", ip, "--type", action, "--reason", reason]
        if duration:
            command.extend(["--duration", duration])
        if action == "unban":
            command = [self.config.cscli_path, "decisions", "delete", "--ip", ip]
        summary = {"execute": execute, "command": command, "ip": ip, "action": action, "reason": reason}
        if not execute:
            summary["status"] = "dry-run"
            return summary
        proc = await asyncio.to_thread(subprocess.run, command, text=True, capture_output=True, check=False)
        summary.update({"status": "executed", "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})
        return summary


async def _run_json(args: list[str]) -> Any:
    proc = await asyncio.to_thread(subprocess.run, args, text=True, capture_output=True, check=True)
    return json.loads(proc.stdout or "[]")


def _decision_from_lapi(item: dict[str, Any]) -> Decision:
    return Decision(
        ip=item.get("value") or item.get("ip"),
        scope=item.get("scope", "Ip"),
        action=item.get("type") or item.get("action", "ban"),
        reason=item.get("reason"),
        scenario=item.get("scenario"),
        country=item.get("country"),
        as_name=item.get("as_name") or item.get("as"),
        until=item.get("until"),
        origin=item.get("origin"),
    )


def _decision_from_cscli(item: dict[str, Any]) -> Decision:
    return Decision(
        ip=item.get("value") or item.get("ip"),
        scope=item.get("scope", "Ip"),
        action=item.get("type") or item.get("action", "ban"),
        reason=item.get("reason"),
        scenario=item.get("scenario"),
        country=item.get("country"),
        as_name=item.get("as_name") or item.get("as"),
        until=item.get("until"),
        origin=item.get("origin"),
    )


def _alert_from_cscli(item: dict[str, Any]) -> CrowdSecAlert:
    source = item.get("source", {}) if isinstance(item.get("source"), dict) else {}
    meta = item.get("meta", {}) if isinstance(item.get("meta"), dict) else {}
    return CrowdSecAlert(
        ip=item.get("source_ip") or source.get("ip") or meta.get("source_ip"),
        scenario=item.get("scenario") or item.get("scenario_hash"),
        country=item.get("source_country") or source.get("country") or meta.get("country"),
        as_name=item.get("source_as_name") or source.get("as_name") or meta.get("as_name"),
        created_at=item.get("created_at") or item.get("start_at"),
        message=item.get("message"),
        events_count=item.get("events_count"),
    )


