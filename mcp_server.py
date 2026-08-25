#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Security Gateway - MCP Server
Exposes Agent Safety Check tools via MCP.

Transport (standalone): stdio -> python mcp_server.py
Transport (HTTP): mounted at /mcp inside FastAPI via main.py

Base URL : SECURITY_API_BASE_URL env var (default: https://agent-security-gateway.onrender.com)
Payment  : MCP_PAYMENT_TOKEN env var -> PAYMENT-SIGNATURE header
"""

import os
import json
import asyncio
from typing import Optional, List, Dict, Any

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

BASE_URL = os.getenv(
    "SECURITY_API_BASE_URL", "https://agent-security-gateway.onrender.com"
).rstrip("/")
PAYMENT_TOKEN = os.getenv("MCP_PAYMENT_TOKEN", "")

PUBLIC_HOST = "agent-security-gateway.onrender.com"
TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[PUBLIC_HOST, f"{PUBLIC_HOST}:*"],
    allowed_origins=[f"https://{PUBLIC_HOST}", f"https://{PUBLIC_HOST}:*"],
)


class _MountedMCPApp:
    """ASGI wrapper that owns Streamable HTTP session-manager lifetime when mounted."""

    def __init__(self, app, session_manager):
        self.app = app
        self.session_manager = session_manager
        self._start_lock = asyncio.Lock()
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._runner_task = None

    async def _runner(self):
        async with self.session_manager.run():
            self._ready.set()
            await self._stop.wait()

    async def _ensure_started(self):
        if self._ready.is_set():
            return
        async with self._start_lock:
            if self._runner_task is None:
                self._runner_task = asyncio.create_task(self._runner())
        while not self._ready.is_set():
            if self._runner_task.done():
                await self._runner_task
            await asyncio.sleep(0)

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            await self._ensure_started()
        await self.app(scope, receive, send)


class MountedFastMCP(FastMCP):
    """FastMCP variant safe for mounting inside an existing FastAPI app."""

    def streamable_http_app(self):
        app = super().streamable_http_app()
        return _MountedMCPApp(app, self.session_manager)


mcp = MountedFastMCP(
    "Agent Security Gateway",
    streamable_http_path="/",
    transport_security=TRANSPORT_SECURITY,
)


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if PAYMENT_TOKEN:
        h["PAYMENT-SIGNATURE"] = PAYMENT_TOKEN
    return h


async def _post(path: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{BASE_URL}{path}", json=payload, headers=_headers())
        if resp.status_code == 402:
            return {"error": "Payment Required (x402)", "x402": resp.json()}
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def security_scan(content: str, content_type: Optional[str] = "prompt", sensitivity: Optional[str] = "medium") -> str:
    result = await _post("/api/security/scan", {"content": content, "content_type": content_type, "sensitivity": sensitivity})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def dry_run_validate(tool_name: str, context: Optional[str] = "", tool_arguments: Optional[Dict[str, Any]] = None, agent_id: Optional[str] = "") -> str:
    result = await _post("/api/tool/dry-run-validate", {"tool_name": tool_name, "context": context or "", "tool_arguments": tool_arguments or {}, "agent_id": agent_id or ""})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def response_sanitize(response_content: str, tool_name: Optional[str] = "", agent_id: Optional[str] = "") -> str:
    result = await _post("/api/tool/response-sanitize", {"response_content": response_content, "tool_name": tool_name or "", "agent_id": agent_id or ""})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def schema_drift_check(original_schema: Dict[str, Any], updated_schema: Dict[str, Any], tool_name: Optional[str] = "", agent_id: Optional[str] = "") -> str:
    result = await _post("/api/schema/drift-check", {"original_schema": original_schema, "updated_schema": updated_schema, "tool_name": tool_name or "", "agent_id": agent_id or ""})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def identity_scope_check(agent_id: str, requested_action: str, declared_scopes: Optional[List[str]] = None, declared_role: Optional[str] = "", target_resource: Optional[str] = "") -> str:
    result = await _post("/api/identity/scope-check", {"agent_id": agent_id, "requested_action": requested_action, "declared_scopes": declared_scopes or [], "declared_role": declared_role or "", "target_resource": target_resource or ""})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def quota_check(agent_id: str, tool_calls_used: Optional[int] = 0, tool_calls_limit: Optional[int] = 100, llm_calls_used: Optional[int] = 0, llm_calls_limit: Optional[int] = 50, payment_amount_used: Optional[float] = 0.0, payment_amount_limit: Optional[float] = 10.0) -> str:
    result = await _post("/api/quota/check", {"agent_id": agent_id, "tool_calls_used": tool_calls_used, "tool_calls_limit": tool_calls_limit, "llm_calls_used": llm_calls_used, "llm_calls_limit": llm_calls_limit, "payment_amount_used": payment_amount_used, "payment_amount_limit": payment_amount_limit})
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def tool_approval_check(payload: Dict[str, Any]) -> str:
    """Run the existing free/stateless tool-use approval gate before execution."""
    result = await _post("/api/tool-approval/check", payload)
    return json.dumps(result, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run()
