#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Security Gateway Lite API
FastAPI server with x402 payment protocol for AI security scanning and threat detection
"""

import os
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
from datetime import datetime, timedelta
import asyncio
import traceback

from payment_verifier import PaymentVerifier
from security_engine import SecurityEngine
from deterministic_validator import DeterministicValidator
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

# Initialize components
payment_verifier = PaymentVerifier()
security_engine = SecurityEngine()
deterministic_validator = DeterministicValidator()

# Startup event
@app.on_event("startup")
async def startup_event():
    await security_db.initialize()
    print("[OK] Agent Security Gateway Lite API startup complete")

# Request models
class SecurityScanRequest(BaseModel):
    content: str
    content_type: str = "text"  # text, code, prompt, message
    sensitivity: str = "medium"  # low, medium, high, critical

class BatchScanRequest(BaseModel):
    contents: List[str]
    content_type: str = "text"

class DeterministicValidateRequest(BaseModel):
    content: str
    rules: List[str] = ["no_api_keys", "no_personal_info", "valid_url", "valid_json", "budget_limit", "file_format"]
    strict_mode: bool = True
    amount_usdc: Optional[float] = None  # budget_limit用
    daily_limit: Optional[float] = None  # budget_limit用
    expected_format: Optional[str] = None  # file_format用

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
            }
        ]
    }

@app.post("/api/security/scan", response_model=SecurityScanResponse)
async def security_scan(request: SecurityScanRequest, http_request: Request):
    """Security scan with x402 payment verification"""

    # Skip payment verification in test mode
    if not TEST_MODE:
        payment_header = http_request.headers.get("X-PAYMENT")
        if not payment_header:
            raise HTTPException(
                status_code=402,
                detail={
                    "x402Version": 1,
                    "accepts": [{
                        "scheme": "exact",
                        "network": "base",
                        "maxAmountRequired": "50000",  # 0.05 USDC
                        "resource": f"{http_request.url}",
                        "description": "AI Security Scan - AIセキュリティスキャン",
                        "mimeType": "application/json",
                        "payTo": WALLET_ADDRESS,
                        "maxTimeoutSeconds": 300,
                        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                        "extra": {"name": "USDC", "version": "2"}
                    }]
                }
            )

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
            raise HTTPException(
                status_code=402,
                detail={
                    "x402Version": 1,
                    "accepts": [{
                        "scheme": "exact",
                        "network": "base",
                        "maxAmountRequired": "100000",  # 0.10 USDC
                        "resource": f"{http_request.url}",
                        "description": "Batch Security Scan - バッチセキュリティスキャン",
                        "mimeType": "application/json",
                        "payTo": WALLET_ADDRESS,
                        "maxTimeoutSeconds": 300,
                        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                        "extra": {"name": "USDC", "version": "2"}
                    }]
                }
            )

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
            raise HTTPException(
                status_code=402,
                detail={
                    "x402Version": 1,
                    "accepts": [{
                        "scheme": "exact",
                        "network": "base",
                        "maxAmountRequired": "30000",  # 0.03 USDC
                        "resource": f"{http_request.url}",
                        "description": "Deterministic Validation - 決定論的バリデーション",
                        "mimeType": "application/json",
                        "payTo": WALLET_ADDRESS,
                        "maxTimeoutSeconds": 300,
                        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                        "extra": {"name": "USDC", "version": "2"}
                    }]
                }
            )

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
            "deterministic_validate": "/api/validate/deterministic",
            "threat_stats": "/api/security/threats",
            "health": "/health",
            "discovery": "/.well-known/x402.json"
        },
        "pricing": {
            "security_scan": f"{PRICE_USDC} USDC",
            "batch_scan": "0.10 USDC",
            "deterministic_validate": "0.03 USDC"
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
            "Deterministic Rule-based Validation",
            "Threat Classification",
            "Content Sanitization",
            "Risk Assessment",
            "x402 Payment Integration"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)