#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Security Gateway - MCP Server
Exposes 6 Agent Safety Check tools via MCP.

Transport (standalone): stdio  →  python mcp_server.py
Transport (HTTP):       mounted at /mcp inside FastAPI via main.py

Base URL : SECURITY_API_BASE_URL env var (default: https://agent-security-gateway.onrender.com)
Payment  : MCP_PAYMENT_TOKEN env var → PAYMENT-SIGNATURE header
"""

import os
import json
from typing import Optional, List, Dict, Any

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.getenv(
    "SECURITY_API_BASE_URL", "https://agent-security-gateway.onrender.com"
).rstrip("/")
PAYMENT_TOKEN = os.getenv("MCP_PAYMENT_TOKEN", "")

mcp = FastMCP("Agent Security Gateway")


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


# ── Tools ──────────────────────────────────────────────────────────────────────

@mcp.tool()
async def security_scan(
    content: str,
    content_type: Optional[str] = "prompt",
    sensitivity: Optional[str] = "medium",
) -> str:
    """
    Scan text for prompt injection, jailbreak attempts, PII, and data exfiltration (0.01 USDC).
    Call before passing any external input to an AI agent or before an x402 payment.

    Args:
        content:      Text to scan (prompt, message, tool response, etc.)
        content_type: "text" / "code" / "prompt" / "message"
        sensitivity:  "low" / "medium" / "high" / "critical"

    Returns:
        JSON with risk_score, risk_level, threats_detected, safe_to_use, recommendations
    """
    result = await _post("/api/security/scan", {
        "content": content,
        "content_type": content_type,
        "sensitivity": sensitivity,
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def dry_run_validate(
    tool_name: str,
    context: Optional[str] = "",
    tool_arguments: Optional[Dict[str, Any]] = None,
    agent_id: Optional[str] = "",
) -> str:
    """
    Validate a tool call before execution — blocks destructive operations (0.01 USDC).
    Catches file deletions, payment actions, secret access, deploy actions, and memory writes.

    Args:
        tool_name:       Name of the tool to validate (e.g. "delete_file", "send_payment")
        context:         Context hint (e.g. "file_deletion", "payment", "read_only", "cleanup")
        tool_arguments:  Arguments dict to inspect for dangerous patterns
        agent_id:        Agent identifier for audit logging

    Returns:
        JSON with allow(bool), decision, risk_level, reasons, recommended_action, primitive
    """
    result = await _post("/api/tool/dry-run-validate", {
        "tool_name": tool_name,
        "context": context or "",
        "tool_arguments": tool_arguments or {},
        "agent_id": agent_id or "",
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def response_sanitize(
    response_content: str,
    tool_name: Optional[str] = "",
    agent_id: Optional[str] = "",
) -> str:
    """
    Sanitize an external tool response before returning it to an AI agent (0.01 USDC).
    Detects prompt injection, hidden instructions, and API key/secret exposure in responses.

    Args:
        response_content: Raw response text from an external tool or API call
        tool_name:        Name of the tool that produced the response (for logging)
        agent_id:         Agent identifier for audit logging

    Returns:
        JSON with allow(bool), decision, risk_level, reasons, recommended_action, primitive
    """
    result = await _post("/api/tool/response-sanitize", {
        "response_content": response_content,
        "tool_name": tool_name or "",
        "agent_id": agent_id or "",
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def schema_drift_check(
    original_schema: Dict[str, Any],
    updated_schema: Dict[str, Any],
    tool_name: Optional[str] = "",
    agent_id: Optional[str] = "",
) -> str:
    """
    Detect risky changes between two versions of a tool schema or OpenAPI spec (0.01 USDC).
    Flags new dangerous fields, type widening, and schema changes that could expand agent permissions.

    Args:
        original_schema: Previously trusted schema (dict/JSON)
        updated_schema:  New schema to compare against (dict/JSON)
        tool_name:       Name of the tool whose schema changed (for logging)
        agent_id:        Agent identifier for audit logging

    Returns:
        JSON with allow(bool), decision, risk_level, drift_detected, changed_fields, reasons
    """
    result = await _post("/api/schema/drift-check", {
        "original_schema": original_schema,
        "updated_schema": updated_schema,
        "tool_name": tool_name or "",
        "agent_id": agent_id or "",
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def identity_scope_check(
    agent_id: str,
    requested_action: str,
    declared_scopes: Optional[List[str]] = None,
    declared_role: Optional[str] = "",
    target_resource: Optional[str] = "",
) -> str:
    """
    Check whether an AI agent's declared scopes permit the requested action (0.01 USDC).
    Blocks privilege escalation — e.g. a reader role attempting a delete operation.

    Args:
        agent_id:         Agent identifier
        requested_action: Action the agent wants to perform (e.g. "delete_record", "send_payment")
        declared_scopes:  Scopes the agent claims to have (e.g. ["read", "write"])
        declared_role:    Role the agent claims (e.g. "reader", "admin", "operator")
        target_resource:  Resource being accessed (e.g. "/api/payments", "db:users")

    Returns:
        JSON with allow(bool), decision, risk_level, missing_scopes, reasons
    """
    result = await _post("/api/identity/scope-check", {
        "agent_id": agent_id,
        "requested_action": requested_action,
        "declared_scopes": declared_scopes or [],
        "declared_role": declared_role or "",
        "target_resource": target_resource or "",
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def quota_check(
    agent_id: str,
    tool_calls_used: Optional[int] = 0,
    tool_calls_limit: Optional[int] = 100,
    llm_calls_used: Optional[int] = 0,
    llm_calls_limit: Optional[int] = 50,
    payment_amount_used: Optional[float] = 0.0,
    payment_amount_limit: Optional[float] = 10.0,
) -> str:
    """
    Check whether an AI agent is within its tool call, LLM call, and payment limits (0.01 USDC).
    Returns block when any limit is exceeded, halting runaway agents before they overspend.

    Args:
        agent_id:              Agent identifier
        tool_calls_used:       Tool calls made in current session
        tool_calls_limit:      Maximum allowed tool calls
        llm_calls_used:        LLM API calls made in current session
        llm_calls_limit:       Maximum allowed LLM calls
        payment_amount_used:   USDC spent so far in current session
        payment_amount_limit:  Maximum allowed USDC spend

    Returns:
        JSON with allow(bool), decision, risk_level, exceeded_limits, reasons
    """
    result = await _post("/api/quota/check", {
        "agent_id": agent_id,
        "tool_calls_used": tool_calls_used,
        "tool_calls_limit": tool_calls_limit,
        "llm_calls_used": llm_calls_used,
        "llm_calls_limit": llm_calls_limit,
        "payment_amount_used": payment_amount_used,
        "payment_amount_limit": payment_amount_limit,
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


# ── Entry point (stdio transport for local / Claude Code usage) ────────────────

if __name__ == "__main__":
    mcp.run()
