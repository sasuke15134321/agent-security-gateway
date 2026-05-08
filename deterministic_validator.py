#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deterministic Validator Engine
AIを使わない決定論的なルールベースバリデーション
"""

import re
import json
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import mimetypes
from decimal import Decimal, InvalidOperation


class DeterministicValidator:
    def __init__(self):
        # API Key detection patterns
        self.api_key_patterns = {
            "openai": r"sk-[A-Za-z0-9]{32,}",
            "anthropic": r"sk-ant-[A-Za-z0-9\-_]{32,}",
            "google": r"AIza[0-9A-Za-z\-_]{35}",
            "generic_bearer": r"Bearer\s+[A-Za-z0-9\-_]{32,}",
            "generic_api_key": r"(?:api[_\-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?",
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "github_token": r"ghp_[A-Za-z0-9]{36}",
            "slack_token": r"xox[bpoa]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}",
            "stripe_key": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"
        }

        # Personal information patterns
        self.personal_info_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})",
            "ssn": r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
            "credit_card": r"\b(?:\d{4}[-.\s]?){3}\d{4}\b",
            "japanese_phone": r"\b0\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{4}\b",
            "japanese_postal": r"\b\d{3}[-.\s]?\d{4}\b",
            "password": r"(?:password|pwd|passwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?",
            "username": r"(?:username|user|login)\s*[:=]\s*['\"]?[A-Za-z0-9_]{3,}['\"]?",
            "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        }

        # URL validation pattern
        self.url_pattern = r"https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$"

        # File format extensions
        self.allowed_file_formats = {
            "text": [".txt", ".md", ".csv", ".log"],
            "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"],
            "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"],
            "code": [".py", ".js", ".html", ".css", ".json", ".xml", ".yaml", ".yml"],
            "archive": [".zip", ".tar", ".gz", ".rar", ".7z"]
        }

        # Budget limit thresholds (USDC)
        self.budget_limits = {
            "low": 10.0,
            "medium": 100.0,
            "high": 1000.0,
            "unlimited": float('inf')
        }

    def validate_content(self, content: str, rules: List[str], strict_mode: bool = True) -> Dict[str, Any]:
        """
        決定論的バリデーション実行

        Args:
            content: 検査対象コンテンツ
            rules: 適用するルールリスト
            strict_mode: 厳密モード（一つでも違反があれば失敗）

        Returns:
            バリデーション結果
        """
        violations = []

        for rule in rules:
            rule_violations = self._apply_rule(rule, content)
            violations.extend(rule_violations)

        # 結果判定
        passed = len(violations) == 0
        if not strict_mode:
            # 非厳密モードでは、criticalでない違反は警告として処理
            critical_violations = [v for v in violations if v.get("severity") == "critical"]
            passed = len(critical_violations) == 0

        return {
            "passed": passed,
            "violations": violations,
            "deterministic": True,
            "ai_used": False,
            "total_violations": len(violations),
            "critical_violations": len([v for v in violations if v.get("severity") == "critical"]),
            "validation_timestamp": self._get_timestamp(),
            "content_hash": self._hash_content(content)
        }

    def _apply_rule(self, rule: str, content: str) -> List[Dict[str, Any]]:
        """個別ルール適用"""
        violations = []

        if rule == "no_api_keys":
            violations.extend(self._check_api_keys(content))
        elif rule == "no_personal_info":
            violations.extend(self._check_personal_info(content))
        elif rule == "valid_url":
            violations.extend(self._check_valid_urls(content))
        elif rule == "valid_json":
            violations.extend(self._check_valid_json(content))
        elif rule == "budget_limit":
            violations.extend(self._check_budget_limit(content))
        elif rule == "file_format":
            violations.extend(self._check_file_format(content))
        else:
            violations.append({
                "rule": rule,
                "matched": "unknown_rule",
                "verdict": "ERROR",
                "severity": "medium",
                "message": f"Unknown validation rule: {rule}"
            })

        return violations

    def _check_api_keys(self, content: str) -> List[Dict[str, Any]]:
        """API キー検出"""
        violations = []

        for key_type, pattern in self.api_key_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                # APIキーを部分的にマスク
                masked_key = matched_text[:8] + "*" * (len(matched_text) - 12) + matched_text[-4:] if len(matched_text) > 12 else "*" * len(matched_text)

                violations.append({
                    "rule": "no_api_keys",
                    "matched": masked_key,
                    "verdict": "BLOCKED",
                    "severity": "critical",
                    "key_type": key_type,
                    "position": match.span(),
                    "message": f"API key detected: {key_type}"
                })

        return violations

    def _check_personal_info(self, content: str) -> List[Dict[str, Any]]:
        """個人情報検出"""
        violations = []

        for info_type, pattern in self.personal_info_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                # 個人情報をマスク
                if info_type == "email":
                    parts = matched_text.split('@')
                    if len(parts) == 2:
                        masked = parts[0][:2] + "*" * (len(parts[0]) - 2) + "@" + parts[1]
                    else:
                        masked = "*" * len(matched_text)
                elif info_type in ["phone", "japanese_phone"]:
                    masked = matched_text[:3] + "*" * (len(matched_text) - 6) + matched_text[-3:]
                else:
                    masked = "*" * len(matched_text)

                violations.append({
                    "rule": "no_personal_info",
                    "matched": masked,
                    "verdict": "BLOCKED",
                    "severity": "high",
                    "info_type": info_type,
                    "position": match.span(),
                    "message": f"Personal information detected: {info_type}"
                })

        return violations

    def _check_valid_urls(self, content: str) -> List[Dict[str, Any]]:
        """URL形式検証"""
        violations = []

        # URLっぽい文字列を検出
        url_candidates = re.finditer(r"https?://[^\s<>\"']+", content, re.IGNORECASE)

        for match in url_candidates:
            url = match.group(0)
            if not re.match(self.url_pattern, url, re.IGNORECASE):
                violations.append({
                    "rule": "valid_url",
                    "matched": url[:50] + "..." if len(url) > 50 else url,
                    "verdict": "INVALID",
                    "severity": "medium",
                    "position": match.span(),
                    "message": "Invalid URL format detected"
                })
            else:
                # 追加チェック: 悪意のあるドメイン
                parsed = urlparse(url)
                suspicious_domains = [
                    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
                    "ow.ly", "tiny.cc", "short.link"
                ]
                if any(domain in parsed.netloc.lower() for domain in suspicious_domains):
                    violations.append({
                        "rule": "valid_url",
                        "matched": url,
                        "verdict": "SUSPICIOUS",
                        "severity": "medium",
                        "position": match.span(),
                        "message": "Suspicious URL shortener detected"
                    })

        return violations

    def _check_valid_json(self, content: str) -> List[Dict[str, Any]]:
        """JSON形式検証"""
        violations = []

        # JSONっぽい構造を検出
        json_candidates = re.finditer(r'[{[].*?[}\]]', content, re.DOTALL)

        for match in json_candidates:
            json_text = match.group(0)
            if len(json_text.strip()) > 2:  # 空でないJSON
                try:
                    json.loads(json_text)
                except json.JSONDecodeError as e:
                    violations.append({
                        "rule": "valid_json",
                        "matched": json_text[:100] + "..." if len(json_text) > 100 else json_text,
                        "verdict": "INVALID",
                        "severity": "low",
                        "position": match.span(),
                        "message": f"Invalid JSON format: {str(e)}"
                    })

        return violations

    def _check_budget_limit(self, content: str) -> List[Dict[str, Any]]:
        """予算制限チェック"""
        violations = []

        # 金額パターンを検出
        money_patterns = [
            r'\$\s*([0-9,]+\.?[0-9]*)',  # $1000, $1,000.50
            r'([0-9,]+\.?[0-9]*)\s*USD[C]?',  # 1000 USDC
            r'([0-9,]+\.?[0-9]*)\s*円',  # 1000円
            r'budget[:\s]+([0-9,]+\.?[0-9]*)',  # budget: 1000
            r'cost[:\s]+([0-9,]+\.?[0-9]*)',  # cost: 1000
        ]

        for pattern in money_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    # 数値抽出
                    amount_str = match.group(1).replace(',', '')
                    amount = float(amount_str)

                    # 高額チェック
                    if amount > self.budget_limits["high"]:
                        violations.append({
                            "rule": "budget_limit",
                            "matched": match.group(0),
                            "verdict": "EXCESSIVE",
                            "severity": "high",
                            "amount": amount,
                            "position": match.span(),
                            "message": f"Excessive budget amount detected: {amount}"
                        })
                    elif amount > self.budget_limits["medium"]:
                        violations.append({
                            "rule": "budget_limit",
                            "matched": match.group(0),
                            "verdict": "WARNING",
                            "severity": "medium",
                            "amount": amount,
                            "position": match.span(),
                            "message": f"High budget amount detected: {amount}"
                        })

                except (ValueError, InvalidOperation):
                    continue

        return violations

    def _check_file_format(self, content: str) -> List[Dict[str, Any]]:
        """ファイル形式チェック"""
        violations = []

        # ファイル名パターンを検出
        file_patterns = [
            r'[\w\-_]+\.[a-zA-Z0-9]{2,10}',  # filename.ext
            r'["\']([^"\']*\.[a-zA-Z0-9]{2,10})["\']',  # "filename.ext"
        ]

        for pattern in file_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                filename = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                # 拡張子抽出
                if '.' in filename:
                    ext = '.' + filename.split('.')[-1].lower()

                    # 危険な拡張子チェック
                    dangerous_extensions = [
                        ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", ".jar",
                        ".ps1", ".sh", ".php", ".asp", ".aspx", ".jsp"
                    ]

                    if ext in dangerous_extensions:
                        violations.append({
                            "rule": "file_format",
                            "matched": filename,
                            "verdict": "BLOCKED",
                            "severity": "critical",
                            "extension": ext,
                            "position": match.span(),
                            "message": f"Dangerous file extension detected: {ext}"
                        })

                    # 許可されていない形式
                    all_allowed = []
                    for formats in self.allowed_file_formats.values():
                        all_allowed.extend(formats)

                    if ext not in all_allowed and ext not in dangerous_extensions:
                        violations.append({
                            "rule": "file_format",
                            "matched": filename,
                            "verdict": "UNKNOWN",
                            "severity": "low",
                            "extension": ext,
                            "position": match.span(),
                            "message": f"Unknown file extension: {ext}"
                        })

        return violations

    def _hash_content(self, content: str) -> str:
        """コンテンツハッシュ生成"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]

    def _get_timestamp(self) -> str:
        """現在時刻取得"""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_supported_rules(self) -> Dict[str, str]:
        """サポートされているルール一覧"""
        return {
            "no_api_keys": "API キーの検出と排除",
            "no_personal_info": "個人情報の検出と保護",
            "valid_url": "URL形式の妥当性検証",
            "valid_json": "JSON形式の妥当性検証",
            "budget_limit": "予算制限の確認",
            "file_format": "ファイル形式の安全性チェック"
        }

    def test_patterns(self) -> Dict[str, bool]:
        """パターンテスト"""
        test_results = {}

        # API Key test
        test_content = "sk-ant-1234567890abcdef my key is sk-1234567890123456789012345678901234567890"
        result = self._check_api_keys(test_content)
        test_results["api_keys"] = len(result) > 0

        # Personal info test
        test_content = "Contact me at test@example.com or call 555-1234"
        result = self._check_personal_info(test_content)
        test_results["personal_info"] = len(result) > 0

        # URL test
        test_content = "Visit https://malicious-site or http://invalid..url"
        result = self._check_valid_urls(test_content)
        test_results["url_validation"] = len(result) > 0

        # JSON test
        test_content = '{"valid": true} and {invalid json'
        result = self._check_valid_json(test_content)
        test_results["json_validation"] = len(result) > 0

        # Budget test
        test_content = "The cost is $50000 USD"
        result = self._check_budget_limit(test_content)
        test_results["budget_limit"] = len(result) > 0

        # File format test
        test_content = "Download virus.exe and script.ps1"
        result = self._check_file_format(test_content)
        test_results["file_format"] = len(result) > 0

        return test_results