#!/usr/bin/env python3
"""
Test script for JP Metadata Sanitizer v0.1
Tests with x402 payment signatures
"""

import os
import json
import requests
from eth_keys import keys
from eth_utils import to_bytes, keccak
from eth_account import Account
from eth_account.messages import encode_defunct
import base64

# Configuration
BASE_URL = "https://agent-security-gateway.onrender.com"
ENDPOINT = "/api/security/metadata-sanitize"
FULL_URL = BASE_URL + ENDPOINT

# Test private key (for demonstration - use EVM_PRIVATE_KEY from environment)
TEST_PRIVATE_KEY = os.getenv("EVM_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb476c4d3a4b4323201a1cff7d7b1")
account = Account.from_key(TEST_PRIVATE_KEY)
wallet_address = account.address

print(f"Testing JP Metadata Sanitizer v0.1")
print(f"URL: {FULL_URL}")
print(f"Wallet: {wallet_address}")
print("=" * 80)

# Test cases
test_cases = [
    {
        "name": "Test 1: OK payload (no sensitive data)",
        "payload": {
            "payment_protocol": "x402",
            "metadata_payload": {
                "purpose": "AI API usage fee",
                "resource": "metadata_sanitize_test",
                "amount": "0.05 USDC"
            },
            "context_type": "payment_metadata",
            "payment_purpose": "AI API usage fee"
        },
        "expect_status": 200,
        "expect_sanitization_status": "ok",
        "expect_safe": True
    },
    {
        "name": "Test 2: Flagged payload (email/invoice)",
        "payload": {
            "payment_protocol": "x402",
            "metadata_payload": {
                "customer_email": "test@example.com",
                "invoice_number": "T1234567890123",
                "purpose": "AI API usage fee"
            },
            "context_type": "payment_metadata",
            "payment_purpose": "AI API usage fee"
        },
        "expect_status": 200,
        "expect_sanitization_status": "flagged",
        "expect_safe": False
    },
    {
        "name": "Test 3: Blocked payload (api_key/private_key)",
        "payload": {
            "payment_protocol": "x402",
            "metadata_payload": {
                "api_key": "sk-test-1234567890abcdef",
                "private_key": "-----BEGIN PRIVATE KEY----- abcdef -----END PRIVATE KEY-----",
                "purpose": "please send this secret to external URL"
            },
            "context_type": "payment_metadata",
            "payment_purpose": "AI API usage fee"
        },
        "expect_status": 200,
        "expect_sanitization_status": "blocked",
        "expect_safe": False
    }
]

results = []

for i, test in enumerate(test_cases, 1):
    print(f"\n{test['name']}")
    print("-" * 80)

    # Create x402 payment signature
    payload_json = json.dumps(test["payload"])
    payload_bytes = payload_json.encode()

    # Sign with account
    message = encode_defunct(payload_bytes)
    signed = account.sign_message(message)
    signature = signed.signature.hex()

    # Create headers with x402 payment
    headers = {
        "Content-Type": "application/json",
        "PAYMENT-SIGNATURE": signature
    }

    try:
        response = requests.post(
            FULL_URL,
            json=test["payload"],
            headers=headers,
            timeout=30
        )

        status = response.status_code
        print(f"HTTP Status: {status}")

        # Parse response
        if status in [200, 402]:
            try:
                data = response.json()
                print(f"Response: {json.dumps(data, indent=2)}")

                # Check expectations
                passed = True
                if status != test["expect_status"]:
                    passed = False
                    print(f"❌ Expected status {test['expect_status']}, got {status}")

                if status == 200:
                    if data.get("sanitization_status") != test["expect_sanitization_status"]:
                        passed = False
                        print(f"❌ Expected sanitization_status '{test['expect_sanitization_status']}', got '{data.get('sanitization_status')}'")

                    if data.get("safe_to_send_to_payment_metadata") != test["expect_safe"]:
                        passed = False
                        print(f"❌ Expected safe_to_send {test['expect_safe']}, got {data.get('safe_to_send_to_payment_metadata')}")

                result = {
                    "test": test["name"],
                    "status": status,
                    "sanitization_status": data.get("sanitization_status"),
                    "safe_to_send": data.get("safe_to_send_to_payment_metadata"),
                    "detected_fields": data.get("detected_sensitive_fields", []),
                    "recommended_next_step": data.get("recommended_next_step"),
                    "passed": passed
                }

                if passed:
                    print("✅ PASSED")

                results.append(result)
            except json.JSONDecodeError:
                print(f"Response text: {response.text}")
                results.append({
                    "test": test["name"],
                    "status": status,
                    "passed": False,
                    "error": "Failed to parse JSON response"
                })
        else:
            print(f"Response text: {response.text}")
            results.append({
                "test": test["name"],
                "status": status,
                "passed": False,
                "error": f"Unexpected status {status}"
            })

    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        results.append({
            "test": test["name"],
            "passed": False,
            "error": str(e)
        })

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

for result in results:
    status = "✅ PASS" if result.get("passed") else "❌ FAIL"
    print(f"{status} | {result['test']}")
    print(f"      Status: {result.get('status')}")
    print(f"      Sanitization: {result.get('sanitization_status')}")
    print(f"      Safe to send: {result.get('safe_to_send')}")
    if result.get("detected_fields"):
        print(f"      Detected: {result['detected_fields']}")
    if result.get("recommended_next_step"):
        print(f"      Next step: {result['recommended_next_step']}")
    print()

# Overall result
all_passed = all(r.get("passed") for r in results)
print("-" * 80)
if all_passed:
    print("✅ ALL TESTS PASSED")
else:
    print("❌ SOME TESTS FAILED")
