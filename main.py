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
from pydantic import BaseModel, Field
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
    title="Agent Security Gateway",
    version="1.0.0",
    description=(
        "Pay-per-request security APIs for autonomous AI agents using x402. "
        "Detect Japanese prompt injection, validate content, scan for threats, "
        "and perform pre-payment security checks. Built for USDC/Base payments."
    )
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
    from fastapi.openapi.utils import get_openapi
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    openapi_schema["info"]["x-guidance"] = (
        "Agent Security Gateway provides x402-paid security tools for autonomous AI agents. "
        "Use /api/security/scan before any external API call to detect Japanese prompt injection. "
        "Use /api/security/pre-payment before x402 payments to check payment metadata safety. "
        "Use /api/validate/deterministic for rule-based content validation without AI. "
        "Useful for AI agent security, prompt injection detection, USDC/Base payments."
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

def paid_operation(amount_usd: str) -> dict:
    return {
        "x-payment-info": {
            "price": {
                "mode": "fixed",
                "currency": "USD",
                "amount": amount_usd,
            },
            "protocols": [{"x402": {}}],
        }
    }

_PAID_ENDPOINTS = {
    ("POST", "/api/security/scan"):          PRICE_USDC,
    ("POST", "/api/security/batch"):         "0.10",
    ("POST", "/api/validate/deterministic"): "0.03",
    ("POST", "/api/security/pre-payment"):   "0.03",
    ("POST", "/api/validate/completeness"):  "0.03",
    ("POST", "/api/validate/list_check"):    "0.01",
    ("POST", "/api/trust/check"):            "0.05",
}

# CDP Bazaar indexing extension for /api/security/scan
_BAZAAR_EXTENSIONS = {
    "bazaar": {
        "info": {
            "input": {
                "type": "http",
                "method": "POST",
                "bodyType": "json",
                "body": {
                    "prompt": "Please summarize this document",
                    "context": "user_input",
                    "check_type": "prompt_injection"
                }
            },
            "output": {
                "type": "json",
                "example": {
                    "safe": True,
                    "threat_detected": False,
                    "threat_type": None,
                    "risk_level": "low",
                    "next_recommended": "proceed_with_x402_payment"
                }
            }
        },
        "schema": {
            "type": "object",
            "properties": {
                "safe": {"type": "boolean"},
                "threat_detected": {"type": "boolean"},
                "threat_type": {"type": "string"},
                "risk_level": {"type": "string"},
                "next_recommended": {"type": "string"}
            }
        }
    }
}

@app.middleware("http")
async def x402_payment_middleware(request: Request, call_next):
    path = request.url.path
    price = _PAID_ENDPOINTS.get((request.method, path))
    if not TEST_MODE and price is not None:
        if not request.headers.get("X-PAYMENT"):
            max_amount = str(round(float(price) * 1_000_000))
            _pc = {
                "x402Version": 2,
                "error": "Payment required",
                "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": max_amount, "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}],
            }
            if path == "/api/security/scan":
                _pc["resource"] = {
                    "url": "https://agent-security-gateway.onrender.com/api/security/scan",
                    "method": "POST",
                    "description": "Security scan for AI agent requests before external API calls or x402 payments",
                    "mimeType": "application/json"
                }
                _pc["extensions"] = _BAZAAR_EXTENSIONS
                _pc["safe"] = False
                _pc["threat_detected"] = False
                _pc["threat_type"] = None
                _pc["risk_level"] = "unknown"
                _pc["next_recommended"] = "complete_x402_payment"
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

class TrustCheckRequest(BaseModel):
    url: str = Field(..., description="API URL to check (e.g. https://example.com)")

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
@app.get("/ai-agent-policy", include_in_schema=False)
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

@app.get("/.well-known/mcp/server-card.json", include_in_schema=False)
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

@app.get("/.well-known/ai-agent-policy", include_in_schema=False)
async def ai_agent_policy():
    import json
    import os
    policy_path = "ai-agent-policy.json"
    if os.path.exists(policy_path):
        with open(policy_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"error": "Policy not found"}

@app.get("/ai-agent-policy.json", include_in_schema=False)
async def ai_agent_policy_json():
    from pathlib import Path
    import json
    policy_path = Path(__file__).parent / "ai-agent-policy.json"
    with open(policy_path) as f:
        return json.load(f)

@app.get("/.well-known/x402.json", include_in_schema=False)
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

@app.get("/.well-known/x402", include_in_schema=False)
async def x402_discovery_manifest():
    return {
        "version": 1,
        "name": "Agent Security Gateway",
        "title": "Agent Security Gateway",
        "description": (
            "Pay-per-request security APIs for autonomous AI agents using x402. "
            "Detect Japanese prompt injection, validate content, and perform pre-payment checks."
        ),
        "tags": ["AI", "Security", "Governance"],
        "resources": [
            "https://agent-security-gateway.onrender.com/api/security/scan",
            "https://agent-security-gateway.onrender.com/api/security/batch",
            "https://agent-security-gateway.onrender.com/api/validate/deterministic",
            "https://agent-security-gateway.onrender.com/api/security/pre-payment",
            "https://agent-security-gateway.onrender.com/api/validate/completeness",
            "https://agent-security-gateway.onrender.com/api/validate/list_check",
            "https://agent-security-gateway.onrender.com/api/trust/check"
        ],
        "ownershipProofs": [
            "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"
        ],
        "instructions": (
            "Agent Security Gateway detects Japanese prompt injection and validates content. "
            "Use /api/security/scan before external API calls. "
            "Use /api/security/pre-payment before x402 payments."
        )
    }

@app.post("/api/security/scan",
    summary="Security Scan - Detect prompt injection and threats",
    description="Scans text for Japanese prompt injection, PII, suspicious patterns, and x402 payment threats. Use before any external API call or x402 payment.",
    tags=["Security"],
    response_model=SecurityScanResponse,
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.05"))
async def security_scan(request: SecurityScanRequest, http_request: Request):
    """Security scan with x402 payment verification"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "50000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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

@app.post("/api/security/batch",
    summary="Batch Security Scan - Scan multiple texts",
    description="Batch scan multiple texts for security threats. Returns threat scores and injection detection results for each input.",
    tags=["Security"],
    response_model=BatchScanResponse,
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.10"))
async def batch_security_scan(request: BatchScanRequest, http_request: Request):
    """Batch security scan with x402 payment verification"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "100000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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

@app.post("/api/validate/deterministic",
    summary="Deterministic Validator - Rule-based content validation",
    description="Validates content using deterministic rules. No AI used. Checks for API keys, PII, URL validity, JSON format, and budget limits.",
    tags=["Security"],
    response_model=DeterministicValidateResponse,
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.03"))
async def deterministic_validate(request: DeterministicValidateRequest, http_request: Request):
    """決定論的バリデーション - AIを使わないルールベース検証 (0.03 USDC)"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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

@app.post("/api/security/pre-payment",
    summary="Pre-Payment Check - Security check before x402 payment",
    description="Performs security check before x402 USDC or JPYC payment. Detects suspicious payment metadata and PII in payment reason text.",
    tags=["Security"],
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.03"))
async def pre_payment_check(request: PrePaymentRequest, http_request: Request):
    """x402支払い前セキュリティチェック (0.03 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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


@app.post("/api/validate/completeness",
    summary="Completeness Validator - Check response completeness",
    description="Validates that AI responses are complete and not truncated. Detects missing fields, incomplete reasoning, and response quality issues.",
    tags=["Security"],
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.03"))
async def validate_completeness(request: CompletenessRequest, http_request: Request):
    """完全性チェック - タスク完了アイテムの網羅性検証 (0.03 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "30000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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


@app.post("/api/validate/list_check",
    summary="List Check - Validate list item counts",
    description="Checks that list items in AI responses match expected counts. Detects missing or extra items in structured responses.",
    tags=["Security"],
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.01"))
async def validate_list_check(request: ListCheckRequest, http_request: Request):
    """件数一致チェック - 期待件数と実際件数の一致検証 (0.01 USDC)"""

    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "10000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
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


@app.post(
    "/api/trust/check",
    summary="API Trust Check - L6 Trust Scanner for AI agent usability",
    description="Checks if an API has machine-readable metadata and x402 payment compliance for AI agent use. Scores content quality, not just existence. Returns trust score, compliance flags, and actionable recommendations.",
    tags=["Trust"],
    responses={402: {"description": "Payment Required"}},
    openapi_extra=paid_operation("0.05")
)
async def trust_check(payload: TrustCheckRequest, request: Request):
    payment_header = request.headers.get("X-PAYMENT")
    if not TEST_MODE and not payment_header:
        _pc = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "50000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x60c402878EfcEcAe5733A88075328Aa2320C39BE", "maxTimeoutSeconds": 300, "resource": {"method": "POST", "mimeType": "application/json"}}], "error": "Payment required"}
        return JSONResponse(status_code=402, content=_pc, headers={"PAYMENT-REQUIRED": base64.b64encode(json.dumps(_pc).encode()).decode()})

    base_url = payload.url.rstrip("/")
    results: Dict[str, Any] = {}
    score = 0
    missing = []
    recommendations = []

    x402_checks: Dict[str, Any] = {}
    policy_checks: Dict[str, Any] = {}
    openapi_payment_checks: Dict[str, Any] = {}

    x402_compliant = False
    openapi_payment_ready = False
    policy_ready = False

    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:

        # 1. llms.txt 存在 (1点)
        try:
            r = await client.get(f"{base_url}/llms.txt")
            results["llms_txt"] = r.status_code == 200
            if results["llms_txt"]:
                score += 1
            else:
                missing.append("llms.txt")
                recommendations.append("Add /llms.txt with API description and usage guidance")
        except Exception:
            results["llms_txt"] = False
            missing.append("llms.txt")

        # 2. OpenAPI 存在 (1点)
        openapi_content = ""
        try:
            r = await client.get(f"{base_url}/openapi.json")
            has_openapi = r.status_code == 200
            if has_openapi:
                openapi_content = r.text
            if not has_openapi:
                r2 = await client.get(f"{base_url}/openapi.yaml")
                has_openapi = r2.status_code == 200
                if has_openapi:
                    openapi_content = r2.text
            results["openapi"] = has_openapi
            if has_openapi:
                score += 1
            else:
                missing.append("openapi.json or openapi.yaml")
                recommendations.append("Publish OpenAPI spec at /openapi.json")
        except Exception:
            results["openapi"] = False
            missing.append("openapi.json or openapi.yaml")

        # 3. skill.md 存在 (1点)
        try:
            r = await client.get(f"{base_url}/skill.md")
            results["skill_md"] = r.status_code == 200
            if results["skill_md"]:
                score += 1
            else:
                missing.append("skill.md")
                recommendations.append("Add /skill.md with use cases and examples")
        except Exception:
            results["skill_md"] = False
            missing.append("skill.md")

        # 4. ai-agent-policy.json 存在 (1点)
        policy_data = None
        try:
            r = await client.get(f"{base_url}/ai-agent-policy.json")
            results["ai_agent_policy"] = r.status_code == 200
            if results["ai_agent_policy"]:
                score += 1
                try:
                    policy_data = r.json()
                except Exception:
                    pass
            else:
                missing.append("ai-agent-policy.json")
                recommendations.append("Add /ai-agent-policy.json with next_recommended and payment info")
        except Exception:
            results["ai_agent_policy"] = False
            missing.append("ai-agent-policy.json")

        # 5. ai-agent-policy.json 中身が十分か (1点) / 9. reason+priority (1点)
        policy_has_reason = False
        if policy_data:
            next_rec = policy_data.get("next_recommended", [])
            orch = policy_data.get("orchestration_flow")
            policy_checks["next_recommended_is_array"] = isinstance(next_rec, list)
            policy_checks["has_orchestration_flow"] = isinstance(orch, list)

            if isinstance(next_rec, list) and len(next_rec) > 0:
                first = next_rec[0] if isinstance(next_rec[0], dict) else {}
                has_api      = bool(first.get("api"))
                has_url      = bool(first.get("url"))
                has_reason   = bool(str(first.get("reason", "")).strip())
                has_priority = bool(str(first.get("priority", "")).strip())
                policy_checks["has_api"]      = has_api
                policy_checks["has_url"]      = has_url
                policy_checks["has_reason"]   = has_reason
                policy_checks["has_priority"] = has_priority

                if has_api and has_url:
                    score += 1  # 中身が十分 (5点目)
                else:
                    recommendations.append("Add orchestration_flow for multi-step AI agent usage")

                if has_reason and has_priority:
                    policy_has_reason = True  # 9点目は後で加算
            else:
                policy_checks.update({"has_api": False, "has_url": False,
                                      "has_reason": False, "has_priority": False})
                recommendations.append("Add orchestration_flow for multi-step AI agent usage")
        elif results.get("ai_agent_policy"):
            policy_checks["parse_error"] = True

        results["next_recommended_with_reason"] = policy_has_reason
        if not policy_has_reason and results.get("ai_agent_policy"):
            recommendations.append("Add reason and priority to next_recommended in ai-agent-policy.json")

        policy_ready = results.get("ai_agent_policy", False) and policy_has_reason

        # 6. /.well-known/x402 manifest 存在 (1点)
        x402_manifest_data = None
        try:
            r = await client.get(f"{base_url}/.well-known/x402")
            results["x402_manifest"] = r.status_code == 200
            if results["x402_manifest"]:
                score += 1
                try:
                    x402_manifest_data = r.json()
                except Exception:
                    pass
            else:
                missing.append(".well-known/x402")
                recommendations.append("Add /.well-known/x402 discovery manifest")
        except Exception:
            results["x402_manifest"] = False
            missing.append(".well-known/x402")

        # /.well-known/x402.json (存在確認 + content quality 補助)
        x402_json_data = None
        try:
            r = await client.get(f"{base_url}/.well-known/x402.json")
            results["x402_json"] = r.status_code == 200
            if not results["x402_json"]:
                missing.append(".well-known/x402.json")
                recommendations.append("Add /.well-known/x402.json for x402 payment discovery")
            else:
                try:
                    x402_json_data = r.json()
                except Exception:
                    pass
        except Exception:
            results["x402_json"] = False
            missing.append(".well-known/x402.json")

        # 7. x402 manifest content quality (0-2点)
        # x402.json (accepts v2形式優先) → x402.json endpoints形式 → x402 manifest
        x402_content_score = 0
        # accepts/endpoints/resources を持つ方を優先して使う
        _known_keys = ("accepts", "endpoints", "resources")
        if x402_json_data and any(k in x402_json_data for k in _known_keys):
            check_data = x402_json_data
        elif x402_manifest_data and any(k in x402_manifest_data for k in _known_keys):
            check_data = x402_manifest_data
        else:
            check_data = x402_json_data or x402_manifest_data

        if check_data:
            m = check_data
            accepts_list   = m.get("accepts")
            endpoints_list = m.get("endpoints")
            resources_list = m.get("resources")

            if isinstance(accepts_list, list) and len(accepts_list) > 0:
                # v2 accepts 形式
                a = accepts_list[0] if isinstance(accepts_list[0], dict) else {}
                has_version  = "version" in m or "x402Version" in m
                has_network  = bool(a.get("network"))
                has_asset    = bool(a.get("asset"))
                pay_to       = a.get("payTo", "")
                has_pay_to   = bool(pay_to)
                pay_to_valid = str(pay_to).startswith("0x") if pay_to else False
                amt          = a.get("amount") if a.get("amount") is not None else a.get("maxAmountRequired")
                has_amount   = amt is not None and str(amt).strip() != ""
                has_resource = bool(a.get("resource") or a.get("endpoint") or a.get("path"))

                x402_checks.update({
                    "format": "v2_accepts",
                    "has_version": has_version,
                    "v2_compliant": bool(has_asset or a.get("scheme")),
                    "has_accepts": True,
                    "has_network": has_network,
                    "has_asset": has_asset,
                    "has_pay_to": has_pay_to,
                    "pay_to_valid": pay_to_valid,
                    "has_amount": has_amount,
                    "has_resource": has_resource,
                })

                if has_network and has_asset and has_pay_to and has_amount and pay_to_valid:
                    x402_content_score = 2
                    x402_compliant = True
                elif has_network and has_amount:
                    x402_content_score = 1

                if not has_pay_to or not pay_to_valid:
                    recommendations.append("Add payTo address to x402 accepts[]")
                if not has_asset:
                    recommendations.append("Add asset (contract address) to x402 accepts[]")
                if not has_amount:
                    recommendations.append("Add amount or maxAmountRequired to x402 accepts[]")

            elif isinstance(endpoints_list, list) and len(endpoints_list) > 0:
                # endpoints 形式 (旧仕様 - 最大1点)
                ep = endpoints_list[0] if isinstance(endpoints_list[0], dict) else {}
                has_network = bool(ep.get("network"))
                has_amount  = bool(ep.get("price") or ep.get("amount"))
                x402_checks.update({
                    "format": "endpoints",
                    "has_version": "version" in m,
                    "v2_compliant": False,
                    "has_accepts": False,
                    "has_network": has_network,
                    "has_asset": False,
                    "has_pay_to": False,
                    "pay_to_valid": False,
                    "has_amount": has_amount,
                    "has_resource": bool(ep.get("path") or ep.get("method")),
                })
                if has_network and has_amount:
                    x402_content_score = 1
                recommendations.append("Add valid x402 manifest with accepts[] array")
                recommendations.append("Add payTo address to x402 accepts[]")
                recommendations.append("Add asset (contract address) to x402 accepts[]")
            elif isinstance(resources_list, list) and len(resources_list) > 0:
                # resources 形式 (url+method オブジェクト配列 - 最大1点)
                ep = resources_list[0] if isinstance(resources_list[0], dict) else {}
                has_url    = bool(ep.get("url")) if isinstance(ep, dict) else isinstance(ep, str)
                has_method = bool(ep.get("method")) if isinstance(ep, dict) else False
                x402_checks.update({
                    "format": "resources",
                    "has_version": "version" in m,
                    "v2_compliant": False,
                    "has_accepts": False,
                    "has_network": False,
                    "has_asset": False,
                    "has_pay_to": False,
                    "pay_to_valid": False,
                    "has_amount": False,
                    "has_resource": has_url,
                })
                if has_url and has_method:
                    x402_content_score = 1
                recommendations.append("Add valid x402 manifest with accepts[] array")
                recommendations.append("Add payTo address to x402 accepts[]")
                recommendations.append("Add asset (contract address) to x402 accepts[]")
            else:
                x402_checks.update({"format": "unknown", "has_accepts": False,
                                    "has_network": False, "has_amount": False})
                recommendations.append("Add valid x402 manifest with accepts[] array")
                recommendations.append("Add amount or maxAmountRequired to x402 accepts[]")
                recommendations.append("Add payTo address to x402 accepts[]")
        else:
            x402_checks.update({"format": "not_found", "has_accepts": False})
            recommendations.append("Add valid x402 manifest with accepts[] array")

        score += x402_content_score
        results["x402_content_quality"] = x402_content_score

        # 8. OpenAPI payment 情報 (1点)
        if openapi_content:
            payment_keywords = ["x-payment-info", "x402", "402", "Payment Required",
                                "paid_operation", "X-PAYMENT"]
            found_kw = [kw for kw in payment_keywords if kw in openapi_content]
            openapi_payment_ready = len(found_kw) > 0
            openapi_payment_checks["found_keywords"] = found_kw
            openapi_payment_checks["payment_ready"] = openapi_payment_ready
        else:
            openapi_payment_checks.update({"found_keywords": [], "payment_ready": False})

        results["openapi_payment_ready"] = openapi_payment_ready
        if openapi_payment_ready:
            score += 1
        else:
            recommendations.append("Add x-payment-info or 402 payment information to OpenAPI")

    # 9. next_recommended reason+priority (1点)
    if policy_has_reason:
        score += 1

    payment_ready = x402_compliant and openapi_payment_ready

    if score >= 9:
        grade = "A"
    elif score >= 7:
        grade = "B"
    elif score >= 5:
        grade = "C"
    elif score >= 3:
        grade = "D"
    else:
        grade = "F"

    return {
        "url": base_url,
        "trust_score": score,
        "max_score": 10,
        "grade": grade,
        "machine_readable_readiness": grade,
        "checks": results,
        "missing": missing,
        "recommendations": recommendations,
        "summary": f"Trust Score: {score}/10 ({grade}). {len(missing)} items missing.",
        "x402_compliant": x402_compliant,
        "payment_ready": payment_ready,
        "policy_ready": policy_ready,
        "openapi_payment_ready": openapi_payment_ready,
        "x402_checks": x402_checks,
        "policy_checks": policy_checks,
        "openapi_payment_checks": openapi_payment_checks,
    }


@app.get("/api/security/threats", response_model=ThreatStatsResponse, include_in_schema=False)
async def get_threat_stats():
    """Get threat detection statistics (free endpoint)"""
    try:
        stats = await security_db.get_threat_statistics()
        return stats
    except Exception as e:
        print(f"[ERROR] Failed to get threat stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get threat statistics: {str(e)}")

@app.get("/health", include_in_schema=False)
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

@app.get("/", include_in_schema=False)
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

@app.get("/llms.txt", include_in_schema=False)
async def llms_txt():
    content = open("llms.txt").read()
    return PlainTextResponse(content)

@app.get("/skill.md", include_in_schema=False)
async def skill_md():
    content = open("skill.md").read()
    return PlainTextResponse(content)

@app.get("/examples.md", include_in_schema=False)
async def examples_md():
    content = open("examples.md").read()
    return PlainTextResponse(content)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)