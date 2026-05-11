#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Security Gateway - MCP Server
Exposes security_scan, pre_payment_check, validate_completeness as MCP tools.

Transport: stdio (default for Claude Code / MCP clients)
Base URL: SECURITY_API_BASE_URL env var (default: https://agent-security-gateway.onrender.com)
Payment:  MCP_PAYMENT_TOKEN env var → X-PAYMENT header (omit when TEST_MODE=true on server)
"""

import os
import json
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.getenv("SECURITY_API_BASE_URL", "https://agent-security-gateway.onrender.com").rstrip("/")
PAYMENT_TOKEN = os.getenv("MCP_PAYMENT_TOKEN", "")

mcp = FastMCP("Agent Security Gateway")


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if PAYMENT_TOKEN:
        h["X-PAYMENT"] = PAYMENT_TOKEN
    return h


async def _post(path: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{BASE_URL}{path}", json=payload, headers=_headers())
        if resp.status_code == 402:
            return {"error": "Payment Required", "detail": resp.json()}
        resp.raise_for_status()
        return resp.json()


# ── Tools ──────────────────────────────────────────────────────────────────────

@mcp.tool()
async def security_scan(
    content: str,
    content_type: Optional[str] = "text",
    sensitivity: Optional[str] = "medium",
) -> str:
    """
    テキストのセキュリティスキャンを実行します (0.05 USDC)。
    プロンプト注入・隠し命令・機密情報流出・ジェイルブレイク等を検出します。

    Args:
        content:      スキャン対象のテキスト
        content_type: コンテンツ種別 - "text" / "code" / "prompt" / "message"
        sensitivity:  検出感度 - "low" / "medium" / "high" / "critical"

    Returns:
        risk_score(0-100), risk_level, threats_detected, safe_to_use,
        recommendations, sanitized_content を含むJSON文字列
    """
    result = await _post("/api/security/scan", {
        "content": content,
        "content_type": content_type,
        "sensitivity": sensitivity,
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def pre_payment_check(
    api_url: str,
    amount_usdc: float,
    agent_id: str,
    api_response_preview: Optional[str] = "",
) -> str:
    """
    x402支払い実行前のセキュリティチェックを行います (0.03 USDC)。
    URL評価・価格妥当性・連続支払い検出・詐欺パターン検出を実行します。

    Args:
        api_url:              支払い先APIのURL
        amount_usdc:          支払い予定金額（USDC）
        agent_id:             エージェントの識別子
        api_response_preview: APIレスポンスのプレビュー（省略可）

    Returns:
        safe_to_pay, risk_score, recommended_action, warnings を含むJSON文字列
    """
    result = await _post("/api/security/pre-payment", {
        "api_url": api_url,
        "amount_usdc": amount_usdc,
        "agent_id": agent_id,
        "api_response_preview": api_response_preview,
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def validate_completeness(
    task: str,
    expected_items: list[str],
    actual_items: list[str],
    match_type: Optional[str] = "exact",
) -> str:
    """
    タスク完了アイテムの網羅性を検証します (0.03 USDC)。
    AIを使わない決定論的チェックで、expected_itemsが全てactual_itemsに含まれるか確認します。

    Args:
        task:           タスク名・説明（ログ用）
        expected_items: 期待するアイテムのリスト
        actual_items:   実際に完了したアイテムのリスト
        match_type:     照合方式 - "exact"（完全一致）/ "contains"（部分一致）/ "pattern"（正規表現）

    Returns:
        complete(bool), missing_items, matched_items, coverage_rate を含むJSON文字列
    """
    result = await _post("/api/validate/completeness", {
        "task": task,
        "expected_items": expected_items,
        "actual_items": actual_items,
        "match_type": match_type,
    })
    return json.dumps(result, ensure_ascii=False, indent=2)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
