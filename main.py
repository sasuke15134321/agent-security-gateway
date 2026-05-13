#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Security Gateway Lite API
FastAPI server with x402 payment protocol for AI security scanning and threat detection
"""

import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import base64
from datetime import datetime, timedelta
import asyncio
import traceback
from fastapi.openapi.utils import get_openapi

from payment_verifier import PaymentVerifier
from security_engine import SecurityEngine
from deterministic_validator import DeterministicValidator
from pre_payment_checker import PrePaymentChecker
from database import security_db

# Environment variables
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS", "0x")
PRICE_USDC = os.getenv("PRICE_USDC", "0.05")
NETWORK = os.getenv("NETWORK", "base-mainnet")
TEST_MODE = os.getenv("TEST_MODE", "true").lower() == "true"

app = FastAPI(
    title="Agent Security Gateway Lite API",
    description="AI security scanning and threat detection service with x402 payment protocol",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["info"]["x-guidance"] = "Call before any x402 payment or external API call. Japanese prompt injection detection. Deterministic validator."

    price_map = {
        "/api/security/scan": "0.05",
        "/api/security/batch": "0.10",
        "/api/validate/deterministic": "0.03",
        "/api/security/pre-payment": "0.03",
        "/api/validate/completeness": "0.03",
        "/api/validate/list_check": "0.01"
    }

    for path, methods in openapi_schema.get("paths", {}).items():
        if path in price_map:
            for method, operation in methods.items():
                if isinstance(operation, dict):
                    operation["x-payment-info"] = {
                        "protocols": ["x402"],
                        "authMode": "x402",
                        "price": {
                            "mode": "fixed",
                            "currency": "USDC",
                            "amount": price_map[path]
                        }
                    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

_PAID_ENDPOINTS = {
    ("POST", "/api/security/scan"):          PRICE_USDC,
    ("POST", "/api/security/batch"):         "0.10",
    ("POST", "/api/validate/deterministic"): "0.03",
    ("POST", "/api/security/pre-payment"):   "0.03",
    ("POST", "/api/validate/completeness"):  "0.03",
    ("POST", "/api/validate/list_check"):    "0.01",
}

@app.middleware("http")
async def x402_payment_middleware(request: Request, call_next):
    price = _PAID_ENDPOINTS.get((request.method, request.url.path))
    if not TEST_MODE and price is not None:
        if not request.headers.get("X-PAYMENT"):
            max_amount = str(round(float(price) * 1_000_000))
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": max_amount, "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})
    return await call_next(request)

# Initialize components
payment_verifier = PaymentVerifier()
security_engine = SecurityEngine()
deterministic_validator = DeterministicValidator()
pre_payment_checker = PrePaymentChecker()

# Startup event
@app.on_event("startup")
async def startup_event():
    try:
        await security_db.initialize()
        print("[OK] Agent Security Gateway Lite API startup complete")
    except Exception as e:
        print(f"[WARN] Database initialization failed (continuing without DB): {e}")
        print("[OK] Agent Security Gateway Lite API started in DB-less mode")

# Request models
class SecurityScanRequest(BaseModel):
    content: str
    content_type: str = "text"  # text, code, prompt, message
    sensitivity: str = "medium"  # low, medium, high, critical

class BatchScanRequest(BaseModel):
    contents: List[str]
    content_type: str = "text"

class PrePaymentRequest(BaseModel):
    api_url: str
    amount_usdc: float
    api_response_preview: str = ""
    agent_id: str

class DeterministicValidateRequest(BaseModel):
    content: str
    rules: List[str] = ["no_api_keys", "no_personal_info", "valid_url", "valid_json", "budget_limit", "file_format"]
    strict_mode: bool = True
    amount_usdc: Optional[float] = None  # budget_limit用
    daily_limit: Optional[float] = None  # budget_limit用
    expected_format: Optional[str] = None  # file_format用

class CompletenessRequest(BaseModel):
    task: str
    expected_items: List[str]
    actual_items: List[str]
    match_type: str = "exact"  # exact, contains, pattern

class ListCheckRequest(BaseModel):
    expected_count: int
    actual_count: int
    label: str = ""

# Response models
class NextRecommendation(BaseModel):
    api_name: str
    url: str
    reason: str
    expected_improvement: str
    price_usdc: float

class SecurityScanResponse(BaseModel):
    risk_score: int
    risk_level: str
    threats_detected: List[str]
    safe_to_use: bool
    recommendations: List[str]
    sanitized_content: str
    next_recommended: NextRecommendation

class BatchScanResponse(BaseModel):
    results: List[SecurityScanResponse]
    summary: Dict[str, Any]
    next_recommended: NextRecommendation

class ThreatStatsResponse(BaseModel):
    total_scans: int
    threats_by_type: Dict[str, int]
    risk_distribution: Dict[str, int]
    top_threats: List[Dict[str, Any]]

class DeterministicValidateResponse(BaseModel):
    passed: bool
    violations: List[Dict[str, Any]]
    deterministic: bool = True
    ai_used: bool = False
    total_violations: int
    critical_violations: int
    validation_timestamp: str
    content_hash: str
    next_recommended: NextRecommendation

# x402 payment protocol endpoint discovery
@app.get("/ai-agent-policy")
async def get_agent_policy():
    """Get AI agent policy information"""
    try:
        with open("ai-agent-policy.json", "r", encoding="utf-8") as f:
            policy = json.load(f)
        return policy
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Agent policy file not found")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid policy file format")

@app.get("/.well-known/mcp/server-card.json")
async def mcp_server_card():
    """Smithery MCP server card - allows Smithery to discover tools without MCP protocol scan"""
    return {
        "serverInfo": {
            "name": "agent-security-gateway",
            "version": "1.0.0"
        },
        "tools": [
            {
                "name": "security_scan",
                "description": "Scan text for prompt injection and threats",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "content_type": {"type": "string"}
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "pre_payment_check",
                "description": "Check API safety before x402 payment",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "api_url": {"type": "string"},
                        "amount_usdc": {"type": "number"}
                    },
                    "required": ["api_url", "amount_usdc"]
                }
            },
            {
                "name": "validate_completeness",
                "description": "Validate task list completeness",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expected_items": {"type": "array"},
                        "actual_items": {"type": "array"}
                    },
                    "required": ["expected_items", "actual_items"]
                }
            }
        ],
        "resources": [],
        "prompts": []
    }

@app.get("/.well-known/ai-agent-policy")
async def ai_agent_policy():
    import json
    import os
    policy_path = "ai-agent-policy.json"
    if os.path.exists(policy_path):
        with open(policy_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"error": "Policy not found"}

@app.get("/.well-known/x402.json")
async def x402_discovery():
    """x402 protocol endpoint discovery for Agentic.Market"""
    return {
        "version": 1,
        "endpoints": [
            {
                "path": "/api/security/scan",
                "method": "POST",
                "price": PRICE_USDC,
                "currency": "USDC",
                "network": "base",
                "description": "AIセキュリティスキャン - プロンプト注入・脅威検出",
                "category": "security",
                "tags": ["ai", "security", "scan", "threat-detection", "prompt-injection"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "ai-security-scanning"
                    }
                }
            },
            {
                "path": "/api/security/batch",
                "method": "POST",
                "price": "0.10",
                "currency": "USDC",
                "network": "base",
                "description": "バッチセキュリティスキャン - 複数テキストの一括脅威検出",
                "category": "security",
                "tags": ["ai", "security", "batch", "bulk-scan", "threat-analysis"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "batch-security-analysis"
                    }
                }
            },
            {
                "path": "/api/validate/deterministic",
                "method": "POST",
                "price": "0.03",
                "currency": "USDC",
                "network": "base",
                "description": "決定論的バリデーション - ルールベースコンテンツ検証",
                "category": "validation",
                "tags": ["validation", "deterministic", "rule-based", "security", "compliance"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "deterministic-validation"
                    }
                }
            },
            {
                "path": "/api/security/pre-payment",
                "method": "POST",
                "price": "0.03",
                "currency": "USDC",
                "network": "base",
                "description": "x402支払い前セキュリティチェック - URL評価・価格妥当性・連続支払い検出・詐欺パターン検出",
                "category": "security",
                "tags": ["x402", "payment", "pre-check", "fraud-detection", "url-reputation"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "x402-pre-payment-security"
                    }
                }
            },
            {
                "path": "/api/validate/completeness",
                "method": "POST",
                "price": "0.03",
                "currency": "USDC",
                "network": "base",
                "description": "完全性チェック - タスク完了アイテムの網羅性検証（exact/contains/pattern）",
                "category": "validation",
                "tags": ["validation", "completeness", "checklist", "deterministic", "task-verification"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "completeness-validation"
                    }
                }
            },
            {
                "path": "/api/validate/list_check",
                "method": "POST",
                "price": "0.01",
                "currency": "USDC",
                "network": "base",
                "description": "件数一致チェック - 期待件数と実際件数の一致検証",
                "category": "validation",
                "tags": ["validation", "count-check", "deterministic", "list-verification"],
                "extensions": {
                    "bazaar": {
                        "discoverable": True,
                        "language": ["ja", "en"],
                        "specialization": "list-count-validation"
                    }
                }
            }
        ]
    }

@app.get("/.well-known/x402")
async def x402_discovery_manifest():
    return {
        "version": 1,
        "resources": [
            "https://agent-security-gateway.onrender.com/api/security/scan",
            "https://agent-security-gateway.onrender.com/api/security/batch",
            "https://agent-security-gateway.onrender.com/api/validate/deterministic",
            "https://agent-security-gateway.onrender.com/api/security/pre-payment",
            "https://agent-security-gateway.onrender.com/api/validate/completeness",
            "https://agent-security-gateway.onrender.com/api/validate/list_check"
        ],
        "ownershipProofs": [
            "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"
        ],
        "instructions": "Japanese prompt injection detection and x402 pre-payment security check API."
    }

@app.post("/api/security/scan", response_model=SecurityScanResponse)
async def security_scan(request: SecurityScanRequest, http_request: Request):
    """Security scan with x402 payment verification"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "50000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, PRICE_USDC)
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        result = await security_engine.scan_content(
            content=request.content,
            content_type=request.content_type,
            sensitivity=request.sensitivity
        )

        # Log scan result
        await security_db.log_scan_result(
            content_hash=security_engine.hash_content(request.content),
            content_type=request.content_type,
            risk_score=result["risk_score"],
            threats_detected=result["threats_detected"],
            sensitivity=request.sensitivity
        )

        # Add cross-sell recommendation
        result["next_recommended"] = {
            "api_name": "Agent Memory API",
            "url": "https://agent-memory-api-bix5.onrender.com",
            "reason": "セキュリティ事故の学習と記憶により、将来的な脅威検出精度を向上",
            "expected_improvement": "35%セキュリティ向上",
            "price_usdc": 0.08
        }

        return result
    except Exception as e:
        print(f"[ERROR] Security scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Security scan failed: {str(e)}")

@app.post("/api/security/batch", response_model=BatchScanResponse)
async def batch_security_scan(request: BatchScanRequest, http_request: Request):
    """Batch security scan with x402 payment verification"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "100000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, "0.10")
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        results = await security_engine.batch_scan_content(
            contents=request.contents,
            content_type=request.content_type
        )

        # Log batch scan results
        for i, content in enumerate(request.contents):
            if i < len(results["results"]):
                result = results["results"][i]
                await security_db.log_scan_result(
                    content_hash=security_engine.hash_content(content),
                    content_type=request.content_type,
                    risk_score=result["risk_score"],
                    threats_detected=result["threats_detected"],
                    sensitivity="medium"  # Default for batch
                )

        # Add cross-sell recommendation to main response
        results["next_recommended"] = {
            "api_name": "Agent Memory API",
            "url": "https://agent-memory-api-bix5.onrender.com",
            "reason": "バッチ処理結果の学習により、大量データのセキュリティパターン分析能力向上",
            "expected_improvement": "40%大量データ処理効率向上",
            "price_usdc": 0.08
        }

        # Add cross-sell recommendation to individual results
        for result in results["results"]:
            result["next_recommended"] = {
                "api_name": "Agent Memory API",
                "url": "https://agent-memory-api-bix5.onrender.com",
                "reason": "個別セキュリティ結果の蓄積学習",
                "expected_improvement": "35%セキュリティ向上",
                "price_usdc": 0.08
            }

        return results
    except Exception as e:
        print(f"[ERROR] Batch security scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch security scan failed: {str(e)}")

@app.post("/api/validate/deterministic", response_model=DeterministicValidateResponse)
async def deterministic_validate(request: DeterministicValidateRequest, http_request: Request):
    """決定論的バリデーション - AIを使わないルールベース検証 (0.03 USDC)"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, "0.03")
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        # 決定論的バリデーション実行 - AIを使わない
        result = deterministic_validator.validate_content(
            content=request.content,
            rules=request.rules,
            amount_usdc=request.amount_usdc,
            daily_limit=request.daily_limit,
            expected_format=request.expected_format,
            strict_mode=request.strict_mode
        )

        # バリデーション結果をデータベースに記録 (エラー時は継続)
        try:
            await security_db.log_validation_result(
                content_hash=result["content_hash"],
                rules_applied=request.rules,
                passed=result["passed"],
                violation_count=result["total_violations"],
                strict_mode=request.strict_mode,
                violations=result["violations"],
                critical_violations=result["critical_violations"]
            )
        except Exception as db_error:
            print(f"[WARNING] Database logging failed: {db_error}")
            # Continue without database logging

        # Add cross-sell recommendation
        result["next_recommended"] = {
            "api_name": "Agent Memory API",
            "url": "https://agent-memory-api-bix5.onrender.com",
            "reason": "バリデーションルールの学習改善と、違反パターンの記憶による精度向上",
            "expected_improvement": "30%バリデーション精度向上",
            "price_usdc": 0.08
        }

        return DeterministicValidateResponse(**result)

    except Exception as e:
        print(f"[ERROR] Deterministic validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Deterministic validation failed: {str(e)}")

@app.post("/api/security/pre-payment")
async def pre_payment_check(request: PrePaymentRequest, http_request: Request):
    """x402支払い前セキュリティチェック (0.03 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, "0.03")
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        import urllib.parse
        api_domain = urllib.parse.urlparse(request.api_url).hostname or request.api_url

        # Fetch recent payment checks for this agent (last 1 hour)
        try:
            recent_calls = await security_db.get_recent_payment_checks(
                agent_id=request.agent_id, hours=1
            )
        except Exception:
            recent_calls = []

        # Run pre-payment checks (deterministic, no AI)
        result = pre_payment_checker.check(
            api_url=request.api_url,
            amount_usdc=request.amount_usdc,
            api_response_preview=request.api_response_preview,
            agent_id=request.agent_id,
            recent_calls=recent_calls,
        )

        # Log this check for future repeat-detection
        try:
            await security_db.log_payment_check(
                agent_id=request.agent_id,
                api_url=request.api_url,
                api_domain=api_domain,
                amount_usdc=request.amount_usdc,
                safe_to_pay=result["safe_to_pay"],
                risk_score=result["risk_score"],
                recommended_action=result["recommended_action"],
                warnings=result["warnings"],
            )
        except Exception as db_err:
            print(f"[WARN] Could not log payment check: {db_err}")

        # Cross-sell: recommend agent-budget-guard for full budget control
        result["next_recommended"] = {
            "api_name": "Agent Budget Guard",
            "url": "https://agent-budget-guard.onrender.com",
            "reason": "完全な予算管理と支払い上限設定のために agent-budget-guard を使用してください",
            "expected_improvement": "AIエージェントの支出を完全にコントロール",
            "price_usdc": 0.03
        }

        return result

    except Exception as e:
        print(f"[ERROR] Pre-payment check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Pre-payment check failed: {str(e)}")


@app.post("/api/validate/completeness")
async def validate_completeness(request: CompletenessRequest, http_request: Request):
    """完全性チェック - タスク完了アイテムの網羅性検証 (0.03 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, "0.03")
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        result = deterministic_validator.check_completeness(
            task=request.task,
            expected_items=request.expected_items,
            actual_items=request.actual_items,
            match_type=request.match_type,
        )

        result["next_recommended"] = {
            "api_name": "Agent Memory API",
            "url": "https://agent-memory-api-bix5.onrender.com",
            "reason": "タスク完了状況の記憶と長期トラッキングにより、継続的な品質改善を実現",
            "expected_improvement": "30%タスク完了率向上",
            "price_usdc": 0.08
        }

        return result

    except Exception as e:
        print(f"[ERROR] Completeness validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Completeness validation failed: {str(e)}")


@app.post("/api/validate/list_check")
async def validate_list_check(request: ListCheckRequest, http_request: Request):
    """件数一致チェック - 期待件数と実際件数の一致検証 (0.01 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 1, "accepts": [{"scheme": "exact", "network": "eip155:8453", "maxAmountRequired": "10000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"}], "error": "Payment required"}
            return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

        is_valid = await payment_verifier.verify_payment(payment_header, WALLET_ADDRESS, "0.01")
        if not is_valid:
            raise HTTPException(status_code=402, detail="Payment verification failed")

    try:
        result = deterministic_validator.check_list_count(
            expected_count=request.expected_count,
            actual_count=request.actual_count,
            label=request.label,
        )

        result["next_recommended"] = {
            "api_name": "Agent Security Gateway",
            "url": "https://agent-security-api.onrender.com",
            "reason": "件数チェック後、コンテンツの完全なセキュリティスキャンで品質を確保",
            "expected_improvement": "25%品質保証向上",
            "price_usdc": 0.05
        }

        return result

    except Exception as e:
        print(f"[ERROR] List count check failed: {e}")
        raise HTTPException(status_code=500, detail=f"List count check failed: {str(e)}")


@app.get("/api/security/threats", response_model=ThreatStatsResponse)
async def get_threat_stats():
    """Get threat detection statistics (free endpoint)"""
    try:
        stats = await security_db.get_threat_statistics()
        return stats
    except Exception as e:
        print(f"[ERROR] Failed to get threat stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get threat statistics: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Test database connectivity
    database_status = "operational"
    try:
        await security_db.test_connection()
    except Exception:
        database_status = "error"

    # Test AI engine
    ai_status = "operational"
    try:
        await security_engine.test_connection()
    except Exception:
        ai_status = "error"

    return {
        "status": "healthy",
        "test_mode": TEST_MODE,
        "network": NETWORK,
        "services": {
            "security_engine": ai_status,
            "database": database_status,
            "payment_verifier": "operational"
        },
        "threat_detection": {
            "prompt_injection": True,
            "hidden_instructions": True,
            "data_exfiltration": True,
            "jailbreak_attempt": True,
            "malicious_url": True,
            "personal_info_leak": True,
            "api_key_exposure": True
        }
    }

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Agent Security Gateway Lite API",
        "description": "AI security scanning and threat detection service",
        "endpoints": {
            "security_scan": "/api/security/scan",
            "batch_scan": "/api/security/batch",
            "pre_payment_check": "/api/security/pre-payment",
            "deterministic_validate": "/api/validate/deterministic",
            "completeness_check": "/api/validate/completeness",
            "list_count_check": "/api/validate/list_check",
            "threat_stats": "/api/security/threats",
            "health": "/health",
            "discovery": "/.well-known/x402.json"
        },
        "pricing": {
            "security_scan": f"{PRICE_USDC} USDC",
            "batch_scan": "0.10 USDC",
            "pre_payment_check": "0.03 USDC",
            "deterministic_validate": "0.03 USDC",
            "completeness_check": "0.03 USDC",
            "list_count_check": "0.01 USDC"
        },
        "network": NETWORK,
        "currency": "USDC",
        "threat_types": [
            "prompt_injection",
            "hidden_instructions",
            "data_exfiltration",
            "jailbreak_attempt",
            "malicious_url",
            "personal_info_leak",
            "api_key_exposure"
        ],
        "features": [
            "Real-time Security Scanning",
            "Batch Processing",
            "x402 Pre-Payment Security Check",
            "Consecutive Payment Detection",
            "URL Reputation Analysis",
            "Fraud Pattern Detection",
            "Deterministic Rule-based Validation",
            "Threat Classification",
            "Content Sanitization",
            "Risk Assessment",
            "x402 Payment Integration"
        ]
    }

@app.get("/llms.txt")
async def llms_txt():
    content = open("llms.txt").read()
    return PlainTextResponse(content)

@app.get("/skill.md")
async def skill_md():
    content = open("skill.md").read()
    return PlainTextResponse(content)

@app.get("/examples.md")
async def examples_md():
    content = open("examples.md").read()
    return PlainTextResponse(content)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)