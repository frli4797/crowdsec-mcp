from __future__ import annotations

import json
import logging
import sys

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp import types

from .analysis import SecurityOps
from .config import Config
from . import __version__

CONFIG = Config.from_env()
ops = SecurityOps(CONFIG)
logger = logging.getLogger(__name__)


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


WINDOW = {"type": "string", "description": "Lookback window such as 15m, 6h, 24h, 7d."}
IP = {"type": "string", "description": "IPv4 or IPv6 address to inspect or operate on."}
LIMIT = {"type": "integer", "default": 20, "minimum": 0, "maximum": 100}
EXECUTE = {
    "type": "boolean",
    "default": False,
    "description": "Legacy no-op flag. The MCP never executes writes; it only prepares an audited potential cscli command.",
}

TOOL_DEFS = [
    types.Tool(
        name="inspect_ip",
        description="Inspect CrowdSec decisions and CrowdSec alerts for one IP.",
        inputSchema=_schema({"ip": IP, "window": WINDOW}, ["ip"]),
    ),
    types.Tool(
        name="security_summary",
        description="Summarize recent CrowdSec decisions and alerts.",
        inputSchema=_schema({"window": WINDOW}),
    ),
    types.Tool(
        name="top_offenders",
        description="Return top source IPs by recent CrowdSec alert volume.",
        inputSchema=_schema({"window": WINDOW}),
    ),
    types.Tool(
        name="recent_crowdsec_decisions",
        description="Return active CrowdSec decisions.",
        inputSchema=_schema({"window": WINDOW}),
    ),
    types.Tool(
        name="decision_inventory",
        description="Summarize active CrowdSec decisions with filters, grouped counts, expiry views, and representative rows.",
        inputSchema=_schema(
            {
                "action": {"type": "string", "description": "Filter by decision action, such as ban or captcha."},
                "origin": {"type": "string", "description": "Filter by decision origin."},
                "scenario": {"type": "string", "description": "Filter by CrowdSec scenario."},
                "country": {"type": "string", "description": "Filter by source country code."},
                "asn": {"type": "string", "description": "Filter by ASN name."},
                "ip": IP,
                "limit": LIMIT,
                "expiring_soon_hours": {"type": "integer", "default": 24, "minimum": 0},
                "long_lived_days": {"type": "integer", "default": 30, "minimum": 0},
            }
        ),
    ),
    types.Tool(
        name="recent_crowdsec_alerts",
        description="Return recent CrowdSec alerts.",
        inputSchema=_schema({"window": WINDOW}),
    ),
    types.Tool(
        name="suggest_scenario",
        description="Suggest a CrowdSec scenario proposal from repeated CrowdSec patterns.",
        inputSchema=_schema({"window": WINDOW}),
    ),
    types.Tool(
        name="unban_ip",
        description="Prepare and audit a potential cscli command to delete a CrowdSec decision for one IP. The MCP does not execute it.",
        inputSchema=_schema({"ip": IP, "reason": {"type": "string"}, "execute": EXECUTE}, ["ip"]),
    ),
    types.Tool(
        name="allow_ip",
        description="Prepare and audit a potential cscli command to add a temporary allow decision for one IP. The MCP does not execute it.",
        inputSchema=_schema(
            {"ip": IP, "duration": {"type": "string", "default": "1h"}, "reason": {"type": "string"}, "execute": EXECUTE},
            ["ip", "reason"],
        ),
    ),
    types.Tool(
        name="ban_ip",
        description="Prepare and audit a potential cscli command to add a CrowdSec ban decision for one IP. The MCP does not execute it.",
        inputSchema=_schema(
            {"ip": IP, "duration": {"type": "string", "default": "4h"}, "reason": {"type": "string"}, "execute": EXECUTE},
            ["ip", "reason"],
        ),
    ),
]


async def inspect_ip(ip: str, window: str | None = None) -> dict:
    """Inspect CrowdSec decisions and alerts for one IP address."""
    return await ops.inspect_ip(ip, window)


async def security_summary(window: str | None = None) -> dict:
    """Summarize recent CrowdSec decisions and alerts."""
    return await ops.security_summary(window)


async def top_offenders(window: str | None = None) -> dict:
    """Return top source IPs by recent CrowdSec alert volume."""
    return await ops.top_offenders(window)


async def recent_crowdsec_decisions(window: str | None = None) -> list[dict]:
    """Return active CrowdSec decisions. Window is accepted for interface consistency."""
    return [d.model_dump() for d in await ops.crowdsec.decisions()]


async def decision_inventory(
    action: str | None = None,
    origin: str | None = None,
    scenario: str | None = None,
    country: str | None = None,
    asn: str | None = None,
    ip: str | None = None,
    limit: int = 20,
    expiring_soon_hours: int = 24,
    long_lived_days: int = 30,
) -> dict:
    """Summarize active CrowdSec decisions with filters, grouped counts, and expiry views."""
    return await ops.decision_inventory(
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


async def recent_crowdsec_alerts(window: str | None = None) -> list[dict]:
    """Return recent CrowdSec alerts."""
    return [a.model_dump() for a in await ops.crowdsec.alerts(window=window)]


async def suggest_scenario(window: str | None = None) -> dict:
    """Suggest a CrowdSec scenario proposal from repeated CrowdSec patterns."""
    return await ops.suggest_scenario(window)


async def unban_ip(ip: str, reason: str | None = None, execute: bool | None = None) -> dict:
    """Prepare an audited potential cscli command to delete a CrowdSec decision for one IP."""
    return await ops.write_action("unban", ip, None, reason or "operator unban via MCP", execute)


async def allow_ip(
    ip: str,
    duration: str | None = "1h",
    reason: str = "temporary operator allowlist via MCP",
    execute: bool | None = None,
) -> dict:
    """Prepare an audited potential cscli command to add a temporary allow decision for one IP."""
    return await ops.write_action("whitelist", ip, duration, reason, execute)


async def ban_ip(
    ip: str,
    duration: str | None = "4h",
    reason: str = "manual operator ban via MCP",
    execute: bool | None = None,
) -> dict:
    """Prepare an audited potential cscli command to add a CrowdSec ban decision for one IP."""
    return await ops.write_action("ban", ip, duration, reason, execute)


async def list_tools(_ctx: object, _params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
    logger.debug("Client requested tool list")
    return types.ListToolsResult(tools=TOOL_DEFS)


async def call_tool(_ctx: object, params: types.CallToolRequestParams) -> types.CallToolResult:
    args = params.arguments or {}
    handlers = {
        "inspect_ip": inspect_ip,
        "security_summary": security_summary,
        "top_offenders": top_offenders,
        "recent_crowdsec_decisions": recent_crowdsec_decisions,
        "decision_inventory": decision_inventory,
        "recent_crowdsec_alerts": recent_crowdsec_alerts,
        "suggest_scenario": suggest_scenario,
        "unban_ip": unban_ip,
        "allow_ip": allow_ip,
        "ban_ip": ban_ip,
    }
    name = params.name
    logger.debug("Client called tool: name=%s args=%s", name, args)
    if name not in handlers:
        logger.debug("Client called unknown tool: name=%s", name)
        raise ValueError(f"Unknown tool: {name}")
    result = await handlers[name](**args)
    logger.debug("Tool completed: name=%s result_type=%s", name, type(result).__name__)
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, sort_keys=True))])


server: Server[dict[str, object]] = Server(
    "crowdsec-ops-mcp",
    version=__version__,
    description="CrowdSec-only MCP server for decisions, alerts, and scoped IP actions.",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


def _configure_logging(config: Config) -> None:
    level = getattr(logging, config.log_level, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _capability_names() -> list[str]:
    return [tool.name for tool in TOOL_DEFS]


async def _main_async() -> None:
    logger.info(
        "Starting crowdsec-ops-mcp: version=%s transport=stdio mode=%s default_window=%s",
        __version__,
        ops.crowdsec.mode,
        CONFIG.default_window,
    )
    logger.info("CrowdSec write audit log: path=%s", CONFIG.write_audit_log_path)
    logger.info("MCP capabilities: tools=%s", ", ".join(_capability_names()))
    await ops.crowdsec.check_lapi()
    async with stdio_server() as (read_stream, write_stream):
        logger.info("crowdsec-ops-mcp is listening: transport=stdio")
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    _configure_logging(CONFIG)
    anyio.run(_main_async)


if __name__ == "__main__":
    main()
