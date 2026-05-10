#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deterministic Validator Engine
AIを使わない決定論的なルールベースバリデーション - if文・正規表現・数値比較のみ
"""

import re
import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime


class DeterministicValidator:
    def __init__(self):
        """決定論的バリデーター初期化 - AIは使用しません"""
        pass

    def validate_content(self, content: str, rules: List[str],
                        amount_usdc: float = None, daily_limit: float = None,
                        expected_format: str = None, strict_mode: bool = True) -> Dict[str, Any]:
        """
        決定論的バリデーション実行 - AIを一切使わない

        Args:
            content: 検査対象コンテンツ
            rules: 適用するルールリスト
            amount_usdc: 予算チェック用金額
            daily_limit: 日次制限額
            expected_format: 期待するファイル形式
            strict_mode: 厳密モード

        Returns:
            バリデーション結果
        """
        violations = []

        # ルールごとにif文で分岐
        for rule in rules:
            if rule == "no_api_keys":
                api_violations = self._check_api_keys_simple(content)
                violations.extend(api_violations)

            elif rule == "no_personal_info":
                info_violations = self._check_personal_info_simple(content)
                violations.extend(info_violations)

            elif rule == "valid_url":
                url_violations = self._check_valid_url_simple(content)
                violations.extend(url_violations)

            elif rule == "valid_json":
                json_violations = self._check_valid_json_simple(content)
                violations.extend(json_violations)

            elif rule == "budget_limit":
                if amount_usdc is not None and daily_limit is not None:
                    budget_violations = self._check_budget_limit_simple(amount_usdc, daily_limit)
                    violations.extend(budget_violations)

            elif rule == "file_format":
                if expected_format is not None:
                    format_violations = self._check_file_format_simple(content, expected_format)
                    violations.extend(format_violations)

        # 結果判定 - if文で決定論的判定
        passed = True
        if len(violations) > 0:
            passed = False

        return {
            "passed": passed,
            "violations": violations,
            "deterministic": True,  # 常にTrue - AIは使わない
            "ai_used": False,  # 常にFalse - AIは使わない
            "total_violations": len(violations),
            "critical_violations": len([v for v in violations if v.get("severity") == "critical"]),
            "validation_timestamp": datetime.now().isoformat(),
            "content_hash": self._hash_content(content)
        }

    def _check_api_keys_simple(self, content: str) -> List[Dict[str, Any]]:
        """①no_api_keys - if文とstring.contains()で実装"""
        violations = []

        # 指定されたパターンをif文でチェック
        if "sk-ant-" in content:
            violations.append({
                "rule": "no_api_keys",
                "matched": "sk-ant-***",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": "Anthropic API key detected"
            })

        if "ghp_" in content:
            violations.append({
                "rule": "no_api_keys",
                "matched": "ghp_***",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": "GitHub API key detected"
            })

        if "Bearer " in content:
            violations.append({
                "rule": "no_api_keys",
                "matched": "Bearer ***",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": "Bearer token detected"
            })

        if "AIza" in content:
            violations.append({
                "rule": "no_api_keys",
                "matched": "AIza***",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": "Google API key detected"
            })

        return violations

    def _check_personal_info_simple(self, content: str) -> List[Dict[str, Any]]:
        """②no_personal_info - 正規表現で実装"""
        violations = []

        # メールアドレス正規表現
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        email_matches = re.findall(email_pattern, content)
        if email_matches:
            violations.append({
                "rule": "no_personal_info",
                "matched": "***@***.***",
                "verdict": "BLOCKED",
                "severity": "high",
                "message": "Email address detected"
            })

        # 電話番号正規表現（US形式）
        phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        phone_matches = re.findall(phone_pattern, content)
        if phone_matches:
            violations.append({
                "rule": "no_personal_info",
                "matched": "***-***-****",
                "verdict": "BLOCKED",
                "severity": "high",
                "message": "Phone number detected"
            })

        # クレジットカード番号正規表現
        cc_pattern = r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        cc_matches = re.findall(cc_pattern, content)
        if cc_matches:
            violations.append({
                "rule": "no_personal_info",
                "matched": "****-****-****-****",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": "Credit card number detected"
            })

        return violations

    def _check_valid_url_simple(self, content: str) -> List[Dict[str, Any]]:
        """③valid_url - if文でhttps://チェック"""
        violations = []

        # URLらしき文字列を検出
        url_pattern = r"https?://[^\s<>\"']+"
        urls = re.findall(url_pattern, content)

        for url in urls:
            # https://で始まるかチェック
            if not url.startswith("https://"):
                violations.append({
                    "rule": "valid_url",
                    "matched": url[:30] + "..." if len(url) > 30 else url,
                    "verdict": "BLOCKED",
                    "severity": "medium",
                    "message": "URL does not start with https://"
                })

        return violations

    def _check_valid_json_simple(self, content: str) -> List[Dict[str, Any]]:
        """④valid_json - JSON.parseで検証"""
        violations = []

        # JSONらしき構造を検出
        json_pattern = r'[{[].*?[}\]]'
        json_candidates = re.findall(json_pattern, content, re.DOTALL)

        for json_text in json_candidates:
            if len(json_text.strip()) > 2:  # 空でないJSON
                try:
                    # JSON.parse equivalent
                    json.loads(json_text)
                except json.JSONDecodeError:
                    violations.append({
                        "rule": "valid_json",
                        "matched": json_text[:50] + "..." if len(json_text) > 50 else json_text,
                        "verdict": "BLOCKED",
                        "severity": "medium",
                        "message": "Invalid JSON format"
                    })

        return violations

    def _check_budget_limit_simple(self, amount_usdc: float, daily_limit: float) -> List[Dict[str, Any]]:
        """⑤budget_limit - 数値比較で実装"""
        violations = []

        # 数値比較 - 超過チェック
        if amount_usdc > daily_limit:
            violations.append({
                "rule": "budget_limit",
                "matched": f"{amount_usdc} USDC",
                "verdict": "BLOCKED",
                "severity": "critical",
                "message": f"Amount {amount_usdc} exceeds daily limit {daily_limit}"
            })

        return violations

    def _check_file_format_simple(self, content: str, expected_format: str) -> List[Dict[str, Any]]:
        """⑥file_format - 文字列比較で実装"""
        violations = []

        # ファイル名を検出
        file_pattern = r'[\w\-_]+\.[a-zA-Z0-9]{2,10}'
        filenames = re.findall(file_pattern, content)

        for filename in filenames:
            # 拡張子抽出
            if '.' in filename:
                actual_ext = '.' + filename.split('.')[-1].lower()
                expected_ext = expected_format.lower()

                # 文字列比較 - 不一致チェック
                if actual_ext != expected_ext:
                    violations.append({
                        "rule": "file_format",
                        "matched": filename,
                        "verdict": "BLOCKED",
                        "severity": "medium",
                        "message": f"File format {actual_ext} does not match expected {expected_ext}"
                    })

        return violations

    def check_completeness(
        self,
        task: str,
        expected_items: List[str],
        actual_items: List[str],
        match_type: str = "exact",
    ) -> Dict[str, Any]:
        """
        アイテムリストの完全性チェック（決定論的・AI不使用）

        match_type:
          exact    - 完全一致
          contains - expected が actual のいずれかに部分一致
          pattern  - expected を正規表現として actual に照合
        """
        missing_items: List[str] = []
        matched_expected: List[str] = []

        for expected in expected_items:
            matched = False

            if match_type == "exact":
                matched = expected in actual_items

            elif match_type == "contains":
                matched = any(expected in actual for actual in actual_items)

            elif match_type == "pattern":
                try:
                    pattern = re.compile(expected, re.IGNORECASE)
                    matched = any(pattern.search(actual) for actual in actual_items)
                except re.error:
                    # 不正な正規表現は exact fallback
                    matched = expected in actual_items

            if matched:
                matched_expected.append(expected)
            else:
                missing_items.append(expected)

        # extra_items: actual にあって expected にないもの（exact のみ算出）
        extra_items: List[str] = []
        if match_type == "exact":
            extra_items = [a for a in actual_items if a not in expected_items]

        total_expected = len(expected_items)
        total_actual = len(actual_items)
        matched_count = len(matched_expected)

        completeness_score = int(matched_count / total_expected * 100) if total_expected > 0 else 100

        if completeness_score == 100:
            verdict = "PASS"
        elif completeness_score >= 80:
            verdict = "WARNING"
        else:
            verdict = "FAIL"

        return {
            "complete": completeness_score == 100,
            "completeness_score": completeness_score,
            "missing_items": missing_items,
            "extra_items": extra_items,
            "total_expected": total_expected,
            "total_actual": total_actual,
            "matched_count": matched_count,
            "match_type": match_type,
            "task": task,
            "verdict": verdict,
            "deterministic": True,
            "ai_used": False,
            "validation_timestamp": datetime.now().isoformat(),
        }

    def check_list_count(
        self,
        expected_count: int,
        actual_count: int,
        label: str = "",
    ) -> Dict[str, Any]:
        """
        件数一致チェック（決定論的・AI不使用）
        """
        match = expected_count == actual_count
        difference = abs(actual_count - expected_count)
        verdict = "PASS" if match else "FAIL"

        return {
            "match": match,
            "difference": difference,
            "expected_count": expected_count,
            "actual_count": actual_count,
            "label": label,
            "verdict": verdict,
            "deterministic": True,
            "ai_used": False,
            "validation_timestamp": datetime.now().isoformat(),
        }

    def _hash_content(self, content: str) -> str:
        """コンテンツハッシュ生成 - 数学的ハッシュ計算"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]

    def get_supported_rules(self) -> List[str]:
        """サポートルール一覧 - 固定リスト"""
        return [
            "no_api_keys",
            "no_personal_info",
            "valid_url",
            "valid_json",
            "budget_limit",
            "file_format"
        ]

    def test_validator(self) -> Dict[str, bool]:
        """バリデーターテスト - 決定論的テスト"""

        # ①API Key test
        api_test = "My key is sk-ant-1234567890"
        api_result = self.validate_content(api_test, ["no_api_keys"])

        # ②Personal info test
        info_test = "Contact: user@example.com or 555-123-4567"
        info_result = self.validate_content(info_test, ["no_personal_info"])

        # ③URL test
        url_test = "Visit http://insecure-site.com"
        url_result = self.validate_content(url_test, ["valid_url"])

        # ④JSON test
        json_test = '{"valid": true} and {invalid json'
        json_result = self.validate_content(json_test, ["valid_json"])

        # ⑤Budget test
        budget_result = self.validate_content("", ["budget_limit"], amount_usdc=150.0, daily_limit=100.0)

        # ⑥Format test
        format_test = "Download file.exe"
        format_result = self.validate_content(format_test, ["file_format"], expected_format=".pdf")

        return {
            "api_keys": not api_result["passed"],
            "personal_info": not info_result["passed"],
            "url_validation": not url_result["passed"],
            "json_validation": not json_result["passed"],
            "budget_limit": not budget_result["passed"],
            "file_format": not format_result["passed"]
        }