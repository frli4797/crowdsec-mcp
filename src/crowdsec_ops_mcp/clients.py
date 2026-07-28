from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import ipaddress
import json
import logging
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .config import Config
from .models import CrowdSecAlert, Decision

logger = logging.getLogger(__name__)

WRITE_ACTIONS = {"ban", "unban", "whitelist"}


class CrowdSecClient:
    def __init__(self, config: Config):
        self.config = config

    @property
    def mode(self) -> str:
        if self.config.crowdsec_lapi_url and self.config.crowdsec_lapi_key:
            return "lapi"
        return "cscli"

    async def check_lapi(self) -> bool:
        if self.mode != "lapi":
            return False
        url = f"{self.config.crowdsec_lapi_url.rstrip('/')}/v1/decisions"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                res = await client.get(
                    url,
                    params={"limit": "1"},
                    headers={"X-Api-Key": self.config.crowdsec_lapi_key},
                )
                res.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("CrowdSec LAPI is unreachable: url=%s error=%s", self.config.crowdsec_lapi_url, exc)
            return False
        logger.info("CrowdSec LAPI is reachable: url=%s", self.config.crowdsec_lapi_url)
        return True

    async def health(self, capabilities: list[str], include_sample_counts: bool = False) -> dict[str, Any]:
        logger.info(
            "Checking CrowdSec backend health: mode=%s include_sample_counts=%s",
            self.mode,
            include_sample_counts,
        )
        lapi = await self._lapi_health()
        cscli = self._cscli_health()
        health: dict[str, Any] = {
            "backend_mode": self.mode,
            "lapi": lapi,
            "cscli": cscli,
            "default_window": self.config.default_window,
            "write_audit_log_path": self.config.write_audit_log_path,
            "exposed_tool_capabilities": capabilities,
            "sample_counts": None,
        }
        if include_sample_counts:
            health["sample_counts"] = await self._sample_counts()
        logger.info(
            "CrowdSec backend health checked: mode=%s lapi_configured=%s lapi_reachable=%s cscli_available=%s",
            health["backend_mode"],
            lapi["configured"],
            lapi["reachable"],
            cscli["available"],
        )
        return health

    async def _lapi_health(self) -> dict[str, Any]:
        url_present = bool(self.config.crowdsec_lapi_url)
        key_present = bool(self.config.crowdsec_lapi_key)
        status: dict[str, Any] = {
            "url_present": url_present,
            "api_key_present": key_present,
            "configured": url_present and key_present,
            "url": _redact_url(self.config.crowdsec_lapi_url),
            "reachable": None,
            "status_code": None,
            "error": None,
        }
        if not status["configured"]:
            logger.info(
                "CrowdSec LAPI health skipped: url_present=%s api_key_present=%s",
                url_present,
                key_present,
            )
            return status
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                res = await client.get(
                    f"{self.config.crowdsec_lapi_url.rstrip('/')}/v1/decisions",
                    params={"limit": "1"},
                    headers={"X-Api-Key": self.config.crowdsec_lapi_key},
                )
            status["status_code"] = res.status_code
            res.raise_for_status()
            status["reachable"] = True
            logger.info("CrowdSec LAPI health check succeeded: url=%s status_code=%s", status["url"], status["status_code"])
        except httpx.HTTPError as exc:
            status["reachable"] = False
            status["error"] = exc.__class__.__name__
            logger.warning("CrowdSec LAPI health check failed: url=%s error=%s", status["url"], exc.__class__.__name__)
        return status

    def _cscli_health(self) -> dict[str, Any]:
        resolved_path = shutil.which(self.config.cscli_path)
        status = {
            "path": self.config.cscli_path,
            "available": resolved_path is not None,
            "resolved_path": resolved_path,
            "relevant": self.mode == "cscli" or not self.config.crowdsec_lapi_url or not self.config.crowdsec_lapi_key,
        }
        logger.info(
            "CrowdSec cscli health checked: path=%s available=%s relevant=%s",
            status["path"],
            status["available"],
            status["relevant"],
        )
        return status

    async def _sample_counts(self) -> dict[str, Any]:
        counts: dict[str, Any] = {
            "window": self.config.default_window,
            "decisions": {"count": None, "error": None},
            "alerts": {"count": None, "error": None},
        }
        try:
            counts["decisions"]["count"] = len(await self.decisions())
        except Exception as exc:
            counts["decisions"]["error"] = exc.__class__.__name__
            logger.warning("CrowdSec health decision sample count failed: error=%s", exc.__class__.__name__)
        try:
            counts["alerts"]["count"] = len(await self.alerts(window=self.config.default_window))
        except Exception as exc:
            counts["alerts"]["error"] = exc.__class__.__name__
            logger.warning("CrowdSec health alert sample count failed: error=%s", exc.__class__.__name__)
        logger.info(
            "CrowdSec health sample counts checked: decisions=%s alerts=%s",
            counts["decisions"]["count"],
            counts["alerts"]["count"],
        )
        return counts

    async def decisions(self, ip: str | None = None) -> list[Decision]:
        if self.config.crowdsec_lapi_url and self.config.crowdsec_lapi_key:
            params = {"ip": ip} if ip else {}
            logger.debug("Fetching CrowdSec decisions from LAPI: url=%s params=%s", self.config.crowdsec_lapi_url, params)
            async with httpx.AsyncClient(timeout=20) as client:
                try:
                    res = await client.get(
                        f"{self.config.crowdsec_lapi_url.rstrip('/')}/v1/decisions",
                        params=params,
                        headers={"X-Api-Key": self.config.crowdsec_lapi_key},
                    )
                    res.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.error(
                        "CrowdSec LAPI request failed: url=%s params=%s error=%s",
                        self.config.crowdsec_lapi_url,
                        params,
                        exc,
                    )
                    raise
                decisions = [_decision_from_lapi(item) for item in res.json()]
                logger.debug("Fetched CrowdSec decisions from LAPI: count=%d", len(decisions))
                return decisions
        args = [self.config.cscli_path, "decisions", "list", "-o", "json"]
        if ip:
            args.extend(["--ip", ip])
        logger.debug("Fetching CrowdSec decisions with cscli: command=%s", args)
        decisions = [_decision_from_cscli(item) for item in await _run_json(args)]
        logger.debug("Fetched CrowdSec decisions with cscli: count=%d", len(decisions))
        return decisions

    async def alerts(self, ip: str | None = None, window: str | None = None) -> list[CrowdSecAlert]:
        args = [self.config.cscli_path, "alerts", "list", "-o", "json", "--since", window or self.config.default_window]
        if ip:
            args.extend(["--ip", ip])
        logger.debug("Fetching CrowdSec alerts with cscli: command=%s", args)
        try:
            rows = await _run_json(args)
        except FileNotFoundError:
            logger.debug("cscli not found while fetching CrowdSec alerts: path=%s", self.config.cscli_path)
            return []
        alerts = [_alert_from_cscli(item) for item in rows]
        logger.debug("Fetched CrowdSec alerts with cscli: count=%d", len(alerts))
        return alerts

    async def write_decision(
        self,
        action: str,
        ip: str,
        duration: str | None,
        reason: str,
        execute: bool,
    ) -> dict[str, Any]:
        _validate_write_action(action)
        ip = _validate_ip(ip)
        command = [self.config.cscli_path, "decisions", "add", "--ip", ip, "--type", action, "--reason", reason]
        if duration:
            command.extend(["--duration", duration])
        if action == "unban":
            command = [self.config.cscli_path, "decisions", "delete", "--ip", ip]
            duration = None
        cscli_command = shlex.join(command)
        summary = {
            "execute_requested": execute,
            "executed": False,
            "command": command,
            "potential_cscli_command": cscli_command,
            "ip": ip,
            "action": action,
            "duration": duration,
            "reason": reason,
            "status": "prepared",
            "note": "This MCP does not execute CrowdSec write actions. Review and run the potential cscli command manually if appropriate.",
        }
        self._audit_write(summary)
        logger.info("Prepared CrowdSec write intent without execution: action=%s ip=%s", action, ip)
        logger.debug("Prepared potential CrowdSec decision command: command=%s", command)
        return summary

    def _audit_write(self, entry: dict[str, Any]) -> None:
        path = Path(self.config.write_audit_log_path)
        if path.parent != Path("."):
            path.parent.mkdir(parents=True, exist_ok=True)
        audit_entry = {"timestamp": datetime.now(UTC).isoformat(), **entry}
        with path.open("a", encoding="utf-8") as audit_log:
            audit_log.write(json.dumps(audit_entry, sort_keys=True) + "\n")


async def _run_json(args: list[str]) -> Any:
    logger.debug("Running command expecting JSON: command=%s", args)
    proc = await asyncio.to_thread(subprocess.run, args, text=True, capture_output=True, check=True)
    return json.loads(proc.stdout or "[]")


def _validate_write_action(action: str) -> None:
    if action not in WRITE_ACTIONS:
        raise ValueError(f"Unsupported CrowdSec write action: {action}")


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address for CrowdSec write action: {ip}") from exc


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


def _redact_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url)
    if not parsed.username and not parsed.password:
        return url
    hostname = parsed.hostname or ""
    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme, hostname, parsed.path, parsed.query, parsed.fragment))
