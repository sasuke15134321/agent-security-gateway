#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pre-Payment Security Checker for x402 payments
Deterministic (no AI) — fast and cheap at 0.03 USDC
"""

import re
import urllib.parse
from typing import Dict, Any, List, Tuple


# Known safe hosting platforms
TRUSTED_DOMAINS = {
    "onrender.com", "railway.app", "vercel.app", "netlify.app",
    "herokuapp.com", "fly.dev", "deno.dev", "workers.dev",
    "github.com", "googleapis.com", "amazonaws.com", "azure.com",
    "cloudflare.com", "fastapi.tiangolo.com",
}

# Suspicious TLD patterns
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".pw", ".cc"}

# URL shorteners (hide actual destination)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "rebrand.ly", "bl.ink"
}

# Common fraud keywords in API description
FRAUD_KEYWORDS = [
    "unlimited", "free money", "hack", "bypass", "exploit",
    "guaranteed profit", "no risk", "100% return", "ponzi",
]

# Standard x402 price tiers (USDC)
STANDARD_PRICE_TIERS = [0.01, 0.02, 0.03, 0.05, 0.08, 0.10, 0.15, 0.20, 0.30, 0.50, 1.00]

# Consecutive call thresholds per agent per domain (within 1 hour)
REPEAT_WARN_THRESHOLD = 3
REPEAT_BLOCK_THRESHOLD = 10


class PrePaymentChecker:

    def check(
        self,
        api_url: str,
        amount_usdc: float,
        api_response_preview: str,
        agent_id: str,
        recent_calls: List[Dict],   # from DB: recent payment_check_logs for this agent
    ) -> Dict[str, Any]:
        """
        Run all pre-payment checks and return a risk assessment.

        Returns:
            {safe_to_pay, risk_score, warnings, reputation_score,
             recommended_action, reason}
        """
        warnings: List[str] = []
        risk_score = 0

        # 1. URL / domain evaluation
        url_risk, url_warns = self._check_url(api_url)
        risk_score += url_risk
        warnings.extend(url_warns)

        # 2. Price validity
        price_risk, price_warns = self._check_price(amount_usdc)
        risk_score += price_risk
        warnings.extend(price_warns)

        # 3. Consecutive payment detection
        repeat_risk, repeat_warns = self._check_consecutive(api_url, agent_id, recent_calls)
        risk_score += repeat_risk
        warnings.extend(repeat_warns)

        # 4. Known fraud pattern detection
        fraud_risk, fraud_warns = self._check_fraud_patterns(api_url, api_response_preview)
        risk_score += fraud_risk
        warnings.extend(fraud_warns)

        # 5. Budget-guard integration hint
        budget_risk, budget_warns = self._check_budget_guard(amount_usdc, recent_calls)
        risk_score += budget_risk
        warnings.extend(budget_warns)

        risk_score = min(100, max(0, risk_score))
        reputation_score = max(0, 100 - risk_score)

        if risk_score < 25:
            recommended_action = "pay"
        elif risk_score < 55:
            recommended_action = "investigate"
        else:
            recommended_action = "skip"

        safe_to_pay = risk_score < 55
        reason = self._build_reason(risk_score, warnings, api_url, amount_usdc)

        return {
            "safe_to_pay": safe_to_pay,
            "risk_score": risk_score,
            "warnings": warnings,
            "reputation_score": reputation_score,
            "recommended_action": recommended_action,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_url(self, api_url: str) -> Tuple[int, List[str]]:
        risk = 0
        warns = []
        try:
            parsed = urllib.parse.urlparse(api_url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""
            tld = "." + hostname.split(".")[-1] if "." in hostname else ""

            if scheme != "https":
                risk += 35
                warns.append(f"Non-HTTPS URL detected ({scheme}://). Payment data may be exposed.")

            # IP address instead of domain
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
                risk += 45
                warns.append("IP address URL detected. Legitimate APIs use domain names.")

            if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
                risk += 60
                warns.append("Localhost URL — this is a local address, not a real API endpoint.")

            if tld in SUSPICIOUS_TLDS:
                risk += 25
                warns.append(f"Suspicious TLD '{tld}' detected. Often associated with low-quality or fraudulent services.")

            if hostname in URL_SHORTENERS:
                risk += 30
                warns.append("URL shortener detected. Actual destination is hidden — cannot verify safety.")

            # Reputation boost for trusted platforms
            domain_parts = hostname.split(".")
            for i in range(len(domain_parts) - 1):
                candidate = ".".join(domain_parts[i:])
                if candidate in TRUSTED_DOMAINS:
                    risk -= 10
                    break

        except Exception:
            risk += 20
            warns.append("Could not parse API URL — malformed URL.")

        return max(0, risk), warns

    def _check_price(self, amount_usdc: float) -> Tuple[int, List[str]]:
        risk = 0
        warns = []

        if amount_usdc <= 0:
            risk += 40
            warns.append(f"Invalid price: {amount_usdc} USDC. Price must be positive.")
        elif amount_usdc > 5.0:
            risk += 25
            warns.append(f"Unusually high price: {amount_usdc} USDC. Verify API value before paying.")
        elif amount_usdc > 2.0:
            risk += 10
            warns.append(f"High price: {amount_usdc} USDC. Confirm this is expected.")

        # Check if price is close to a standard tier
        closest = min(STANDARD_PRICE_TIERS, key=lambda t: abs(t - amount_usdc))
        if abs(closest - amount_usdc) > 0.005 and amount_usdc <= 2.0:
            risk += 10
            warns.append(
                f"Price {amount_usdc} USDC is non-standard. Closest standard tier: {closest} USDC."
            )

        return risk, warns

    def _check_consecutive(
        self, api_url: str, agent_id: str, recent_calls: List[Dict]
    ) -> Tuple[int, List[str]]:
        risk = 0
        warns = []

        try:
            target_domain = urllib.parse.urlparse(api_url).hostname or api_url
        except Exception:
            target_domain = api_url

        same_domain_calls = [
            c for c in recent_calls
            if (urllib.parse.urlparse(c.get("api_url", "")).hostname or "") == target_domain
        ]

        count = len(same_domain_calls)
        if count >= REPEAT_BLOCK_THRESHOLD:
            risk += 50
            warns.append(
                f"Excessive repeat calls: {count} calls to {target_domain} in the last hour. "
                "Possible infinite loop — payments blocked."
            )
        elif count >= REPEAT_WARN_THRESHOLD:
            risk += 25
            warns.append(
                f"Repeat payment alert: {count} calls to {target_domain} in the last hour. "
                "Verify this is intentional."
            )

        return risk, warns

    def _check_fraud_patterns(
        self, api_url: str, api_response_preview: str
    ) -> Tuple[int, List[str]]:
        risk = 0
        warns = []
        combined = (api_url + " " + api_response_preview).lower()

        for keyword in FRAUD_KEYWORDS:
            if keyword in combined:
                risk += 20
                warns.append(f"Suspicious keyword detected in API description: '{keyword}'")

        # Suspicious path patterns
        suspicious_paths = ["/steal", "/exfil", "/dump", "/harvest", "/exploit"]
        for path in suspicious_paths:
            if path in api_url.lower():
                risk += 35
                warns.append(f"Suspicious path '{path}' in URL.")

        return risk, warns

    def _check_budget_guard(
        self, amount_usdc: float, recent_calls: List[Dict]
    ) -> Tuple[int, List[str]]:
        """
        Lightweight budget check.
        Full budget management: use agent-budget-guard API separately.
        """
        risk = 0
        warns = []

        # Estimate hourly spend from recent calls
        total_recent_spend = sum(c.get("amount_usdc", 0) for c in recent_calls)

        if total_recent_spend + amount_usdc > 2.0:
            risk += 15
            warns.append(
                f"Cumulative spend in last hour: {total_recent_spend:.3f} USDC + "
                f"this payment {amount_usdc} USDC = {total_recent_spend + amount_usdc:.3f} USDC. "
                "Consider using agent-budget-guard for full budget control."
            )

        return risk, warns

    def _build_reason(
        self, risk_score: int, warnings: List[str], api_url: str, amount_usdc: float
    ) -> str:
        if risk_score < 25:
            return (
                f"API endpoint {api_url} passed all security checks. "
                f"Price {amount_usdc} USDC is within normal range. Safe to proceed."
            )
        elif risk_score < 55:
            first_warn = warnings[0] if warnings else "Multiple minor risk factors detected."
            return (
                f"Risk score {risk_score}/100 — manual review recommended. "
                f"Primary concern: {first_warn}"
            )
        else:
            first_warn = warnings[0] if warnings else "High-risk indicators detected."
            return (
                f"Risk score {risk_score}/100 — payment not recommended. "
                f"Reason: {first_warn}"
            )
