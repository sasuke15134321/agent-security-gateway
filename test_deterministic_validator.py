#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Deterministic Validator functionality
決定論的バリデーター機能のテストスクリプト
"""

import asyncio
import json
from fastapi.testclient import TestClient
from main import app
from deterministic_validator import DeterministicValidator


def test_deterministic_validator_engine():
    """決定論的バリデーターエンジンのテスト"""
    print("=== Deterministic Validator Engine Test ===")

    validator = DeterministicValidator()

    # Test content with various violations
    test_content = """
    Here's my API key: sk-ant-1234567890abcdef1234567890abcdef
    Contact me at john.doe@example.com or call 555-123-4567
    Visit https://bit.ly/suspicious-link for more info
    Download the file: malware.exe
    The budget is $150,000 USD
    Invalid JSON: {"key": value missing quote}
    """

    # Test with all rules
    result = validator.validate_content(
        content=test_content,
        rules=["no_api_keys", "no_personal_info", "valid_url", "valid_json", "budget_limit", "file_format"],
        strict_mode=True
    )

    print(f"Validation Passed: {result['passed']}")
    print(f"Total Violations: {result['total_violations']}")
    print(f"Critical Violations: {result['critical_violations']}")
    print(f"Deterministic: {result['deterministic']}")
    print(f"AI Used: {result['ai_used']}")

    print("\nViolations:")
    for violation in result['violations']:
        print(f"  - Rule: {violation['rule']}")
        print(f"    Matched: {violation['matched']}")
        print(f"    Verdict: {violation['verdict']}")
        print(f"    Severity: {violation['severity']}")
        if 'message' in violation:
            print(f"    Message: {violation['message']}")
        print()

    print(f"Pattern Tests: {validator.test_patterns()}")
    print(f"Supported Rules: {validator.get_supported_rules()}")


def test_deterministic_validator_api():
    """決定論的バリデーターAPIエンドポイントのテスト"""
    print("\n=== Deterministic Validator API Test ===")

    client = TestClient(app)

    # Test content with API key violation
    test_request = {
        "content": "My OpenAI key is sk-1234567890123456789012345678901234567890 please keep it safe",
        "rules": ["no_api_keys", "no_personal_info"],
        "strict_mode": True
    }

    print("Testing API endpoint...")
    response = client.post("/api/validate/deterministic", json=test_request)

    print(f"Status Code: {response.status_code}")

    if response.status_code == 200:
        result = response.json()
        print(f"API Response:")
        print(f"  Passed: {result['passed']}")
        print(f"  Total Violations: {result['total_violations']}")
        print(f"  Critical Violations: {result['critical_violations']}")
        print(f"  Deterministic: {result['deterministic']}")
        print(f"  AI Used: {result['ai_used']}")
        print(f"  Content Hash: {result['content_hash']}")

        if result['violations']:
            print("  Violations:")
            for violation in result['violations']:
                print(f"    - {violation['rule']}: {violation['verdict']} ({violation['matched']})")
    else:
        print(f"Error: {response.text}")


def test_individual_rules():
    """個別ルールのテスト"""
    print("\n=== Individual Rules Test ===")

    validator = DeterministicValidator()

    test_cases = {
        "no_api_keys": [
            "sk-ant-1234567890abcdef1234567890abcdef",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "AIzaSyDxVlAaP9zKwVgw5z5X5x5x5x5x5x5x5x5"
        ],
        "no_personal_info": [
            "john.doe@example.com",
            "Call me at 555-123-4567",
            "SSN: 123-45-6789",
            "Credit card: 4532-1234-5678-9012"
        ],
        "valid_url": [
            "https://bit.ly/short",
            "http://192.168.1.1/admin",
            "https://example..com/invalid"
        ],
        "valid_json": [
            '{"valid": true}',
            '{invalid: json}',
            '{"missing": quote}'
        ],
        "budget_limit": [
            "The cost is $50,000 USD",
            "Budget: 200000 yen",
            "Price: $5"
        ],
        "file_format": [
            "download.exe",
            "script.ps1",
            "document.pdf",
            "image.jpg"
        ]
    }

    for rule, test_contents in test_cases.items():
        print(f"\n--- Testing Rule: {rule} ---")
        for i, content in enumerate(test_contents, 1):
            result = validator.validate_content(content, [rule], strict_mode=True)
            passed_status = "✓ PASS" if result['passed'] else "✗ VIOLATION"
            violations = len(result['violations'])
            print(f"  Test {i}: {passed_status} ({violations} violations) - {content[:50]}...")


def test_strict_vs_non_strict():
    """厳密モードと非厳密モードの比較"""
    print("\n=== Strict vs Non-Strict Mode Test ===")

    validator = DeterministicValidator()

    # Content with mixed severity violations
    test_content = """
    Contact: user@example.com (medium severity)
    API Key: sk-ant-critical123456789012345678901234 (critical severity)
    Visit: https://example.com (no violation)
    """

    # Test strict mode
    strict_result = validator.validate_content(
        content=test_content,
        rules=["no_api_keys", "no_personal_info", "valid_url"],
        strict_mode=True
    )

    # Test non-strict mode
    non_strict_result = validator.validate_content(
        content=test_content,
        rules=["no_api_keys", "no_personal_info", "valid_url"],
        strict_mode=False
    )

    print(f"Strict Mode:")
    print(f"  Passed: {strict_result['passed']}")
    print(f"  Total Violations: {strict_result['total_violations']}")
    print(f"  Critical Violations: {strict_result['critical_violations']}")

    print(f"Non-Strict Mode:")
    print(f"  Passed: {non_strict_result['passed']}")
    print(f"  Total Violations: {non_strict_result['total_violations']}")
    print(f"  Critical Violations: {non_strict_result['critical_violations']}")


def test_health_check():
    """ヘルスチェックテスト"""
    print("\n=== Health Check Test ===")

    client = TestClient(app)
    response = client.get("/health")

    print(f"Health Check Status: {response.status_code}")
    if response.status_code == 200:
        health_data = response.json()
        print(f"Services Status:")
        for service, status in health_data.get('services', {}).items():
            print(f"  {service}: {status}")

        threat_detection = health_data.get('threat_detection', {})
        print(f"Threat Detection Capabilities: {sum(threat_detection.values())} active")


def test_x402_discovery():
    """x402プロトコル発見エンドポイントテスト"""
    print("\n=== x402 Discovery Test ===")

    client = TestClient(app)
    response = client.get("/.well-known/x402.json")

    print(f"Discovery Status: {response.status_code}")
    if response.status_code == 200:
        discovery_data = response.json()
        endpoints = discovery_data.get('endpoints', [])
        print(f"Available Endpoints: {len(endpoints)}")

        for endpoint in endpoints:
            print(f"  {endpoint['method']} {endpoint['path']} - {endpoint['price']} {endpoint['currency']}")
            print(f"    Description: {endpoint['description']}")


def main():
    """メインテスト実行"""
    print("🔧 Agent Security API - Deterministic Validator Tests")
    print("=" * 70)

    # Run all tests
    test_deterministic_validator_engine()
    test_deterministic_validator_api()
    test_individual_rules()
    test_strict_vs_non_strict()
    test_health_check()
    test_x402_discovery()

    print("\n" + "=" * 70)
    print("✅ All Deterministic Validator tests completed!")
    print("決定論的バリデーター機能のテストが完了しました")


if __name__ == "__main__":
    main()