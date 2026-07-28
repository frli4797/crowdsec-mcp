from __future__ import annotations

import json

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp import types

from .analysis import SecurityOps
from .config import Config

ops = SecurityOps(Config.from_env())


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


WINDOW = {"type": "string", "description": "Lookback window such as 15m, 6h, 24h, 7d."}
IP = {"type": "string", "description": "IPv4 or IPv6 address to inspect or operate on."}
EXECUTE = {"type": "boolean", "default": False, "description": "Run the action. False returns a dry-run summary."}

TOOL_DEFS = [
    types.Tool(
        name="inspect_ip",
        description="Inspect CrowdSec decisions and CrowdSec alerts for one IP.",
        inputSchema=_schema({"ip": IP, "window": WINDOW}, ["ip"]),
    ),
    types.Tool(
        name="security_summary",
        description="Summarize recent homelab security activity.",
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
        description="Dry-run by default. Delete a CrowdSec decision for one IP when execute is true.",
        inputSchema=_schema({"ip": IP, "reason": {"type": "string"}, "execute": EXECUTE}, ["ip"]),
    ),
    types.Tool(
        name="allow_ip",
        description="Dry-run by default. Add a temporary allow decision for one IP when execute is true.",
        inputSchema=_schema(
            {"ip": IP, "duration": {"type": "string", "default": "1h"}, "reason": {"type": "string"}, "execute": EXECUTE},
            ["ip", "reason"],
        ),
    ),
    types.Tool(
        name="ban_ip",
        description="Dry-run by default. Add a CrowdSec ban decision for one IP when execute is true.",
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
    """Summarize recent homelab security activity."""
    return await ops.security_summary(window)


async def top_offenders(window: str | None = None) -> dict:
    """Return top source IPs by recent CrowdSec alert volume."""
    return await ops.top_offenders(window)


async def recent_crowdsec_decisions(window: str | None = None) -> list[dict]:
    """Return active CrowdSec decisions. Window is accepted for interface consistency."""
    return [d.model_dump() for d in await ops.crowdsec.decisions()]


async def recent_crowdsec_alerts(window: str | None = None) -> list[dict]:
    """Return recent CrowdSec alerts."""
    return [a.model_dump() for a in await ops.crowdsec.alerts(window=window)]


async def suggest_scenario(window: str | None = None) -> dict:
    """Suggest a CrowdSec scenario proposal from repeated CrowdSec patterns."""
    return await ops.suggest_scenario(window)


async def unban_ip(ip: str, reason: str | None = None, execute: bool = False) -> dict:
    """Dry-run by default. Delete a CrowdSec decision for one IP when execute is true."""
    return await ops.write_action("unban", ip, None, reason or "operator unban via MCP", execute)


async def allow_ip(ip: str, duration: str | None = "1h", reason: str = "temporary operator allowlist via MCP", execute: bool = False) -> dict:
    """Dry-run by default. Add a temporary allow decision for one IP when execute is true."""
    return await ops.write_action("whitelist", ip, duration, reason, execute)


async def ban_ip(ip: str, duration: str | None = "4h", reason: str = "manual operator ban via MCP", execute: bool = False) -> dict:
    """Dry-run by default. Add a CrowdSec ban decision for one IP when execute is true."""
    return await ops.write_action("ban", ip, duration, reason, execute)


async def list_tools(_ctx: object, _params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOL_DEFS)


async def call_tool(_ctx: object, params: types.CallToolRequestParams) -> types.CallToolResult:
    args = params.arguments or {}
    handlers = {
        "inspect_ip": inspect_ip,
        "security_summary": security_summary,
        "top_offenders": top_offenders,
        "recent_crowdsec_decisions": recent_crowdsec_decisions,
        "recent_crowdsec_alerts": recent_crowdsec_alerts,
        "suggest_scenario": suggest_scenario,
        "unban_ip": unban_ip,
        "allow_ip": allow_ip,
        "ban_ip": ban_ip,
    }
    name = params.name
    if name not in handlers:
        raise ValueError(f"Unknown tool: {name}")
    result = await handlers[name](**args)
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, sort_keys=True))])


server: Server[dict[str, object]] = Server(
    "crowdsec-ops-mcp",
    version="0.1.0",
    description="CrowdSec-focused MCP server for homelab security operations.",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def _main_async() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    anyio.run(_main_async)


if __name__ == "__main__":
    main()
