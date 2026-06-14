#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test real x402 payment for JP Metadata Sanitizer v0.1
Endpoint: https://agent-security-gateway.onrender.com/api/security/metadata-sanitize
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

EVM_PRIVATE_KEY = os.getenv("EVM_PRIVATE_KEY")
if not EVM_PRIVATE_KEY:
    print("[ERROR] EVM_PRIVATE_KEY is not set. Create a .env file or set environment variable.")
    sys.exit(1)

from eth_account import Account
from x402 import x402ClientSync
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.http.clients.requests import wrapRequestsWithPayment
import requests
import json

account = Account.from_key(EVM_PRIVATE_KEY)
print(f"[INFO] Wallet address: {account.address}")

signer = EthAccountSigner(account)
client = x402ClientSync()
register_exact_evm_client(client, signer, networks="eip155:8453")

session = wrapRequestsWithPayment(requests.Session(), client)

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
        "expect_sanitization_status": "blocked",
        "expect_safe": False
    }
]

url = "https://agent-security-gateway.onrender.com/api/security/metadata-sanitize"
print(f"\n[INFO] Target endpoint: {url}")
print(f"[INFO] Network: eip155:8453 (Base Mainnet)")
print(f"[INFO] Amount: 0.05 USDC per call")
print("=" * 80)

results = []

for i, test_case in enumerate(test_cases, 1):
    print(f"\n{test_case['name']}")
    print("-" * 80)

    try:
        response = session.post(url, json=test_case["payload"])
        status = response.status_code

        print(f"HTTP Status: {status}")

        if status == 200:
            data = response.json()

            # Print response
            print(f"Sanitization Status: {data.get('sanitization_status')}")
            print(f"Safe to Send: {data.get('safe_to_send_to_payment_metadata')}")

            if data.get("detected_sensitive_fields"):
                print(f"Detected Fields: {', '.join(data['detected_sensitive_fields'])}")

            if data.get("recommended_next_step"):
                print(f"Recommended Next Step: {data['recommended_next_step']}")

            # Check expectations
            passed = True
            if data.get("sanitization_status") != test_case["expect_sanitization_status"]:
                passed = False
                print(f"[ERROR] Expected sanitization_status '{test_case['expect_sanitization_status']}', got '{data.get('sanitization_status')}'")

            if data.get("safe_to_send_to_payment_metadata") != test_case["expect_safe"]:
                passed = False
                print(f"[ERROR] Expected safe_to_send {test_case['expect_safe']}, got {data.get('safe_to_send_to_payment_metadata')}")

            result = {
                "test": test_case["name"],
                "status": status,
                "sanitization_status": data.get("sanitization_status"),
                "safe_to_send": data.get("safe_to_send_to_payment_metadata"),
                "detected_fields": data.get("detected_sensitive_fields", []),
                "recommended_next_step": data.get("recommended_next_step"),
                "passed": passed
            }

            if passed:
                print("[PASS]")
            else:
                print("[FAIL]")

            results.append(result)

        elif status == 402:
            print("[ERROR] HTTP 402 Payment Required")
            try:
                error = response.json()
                print(f"Error: {error}")
            except:
                print(f"Response: {response.text}")

            result = {
                "test": test_case["name"],
                "status": status,
                "passed": False,
                "error": "Payment Required"
            }
            results.append(result)

        else:
            print(f"[ERROR] HTTP {status}")
            try:
                error = response.json()
                print(f"Error: {error}")
            except:
                print(f"Response: {response.text}")

            result = {
                "test": test_case["name"],
                "status": status,
                "passed": False,
                "error": f"HTTP {status}"
            }
            results.append(result)

    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        result = {
            "test": test_case["name"],
            "passed": False,
            "error": str(e)
        }
        results.append(result)

# Print summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

for result in results:
    status_str = "[PASS]" if result.get("passed") else "[FAIL]"
    print(f"{status_str} {result['test']}")
    print(f"     Status: {result.get('status')}")
    print(f"     Sanitization: {result.get('sanitization_status')}")
    print(f"     Safe to send: {result.get('safe_to_send')}")
    if result.get("detected_fields"):
        print(f"     Detected: {', '.join(result['detected_fields'])}")
    if result.get("recommended_next_step"):
        print(f"     Next step: {result['recommended_next_step']}")
    print()

# Overall result
print("-" * 80)
all_passed = all(r.get("passed") for r in results)
if all_passed:
    print("[ALL TESTS PASSED]")
    sys.exit(0)
else:
    print("[SOME TESTS FAILED]")
    sys.exit(1)
