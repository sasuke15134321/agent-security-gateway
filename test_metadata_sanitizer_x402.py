#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test real x402 payment for JP Metadata Sanitizer v0.1
Endpoint: /api/security/metadata-sanitize
"""
import asyncio
import base64
import json
import os
import sys
import httpx
from x402.mechanisms.evm.exact import create_exact_evm_payment
from eth_account import Account

# Configuration
BASE_URL = "https://agent-security-gateway.onrender.com"
ENDPOINT = "/api/security/metadata-sanitize"
FULL_URL = BASE_URL + ENDPOINT
WALLET_ADDRESS = "0x60c402878EfcEcAe5733A88075328Aa2320C39BE"
AMOUNT_USDC = 0.05
NETWORK = "eip155:8453"  # Base mainnet
USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# Test cases
TEST_CASES = [
    {
        "name": "Test 1: OK payload (no sensitive data)",
        "request": {
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
        "request": {
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
        "request": {
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


async def test_metadata_sanitizer():
    """Execute real x402 payment to /api/security/metadata-sanitize"""
    private_key = os.getenv("EVM_PRIVATE_KEY")
    if not private_key:
        print("[ERROR] EVM_PRIVATE_KEY not set in environment")
        return False

    try:
        # Create account from private key
        account = Account.from_key(private_key)
        print(f"[INFO] Wallet address: {account.address}")
        print(f"[INFO] Target endpoint: {FULL_URL}")
        print(f"[INFO] Amount: {AMOUNT_USDC} USDC")
        print(f"[INFO] Network: {NETWORK}")
        print("=" * 80)

        # Create x402 payment payload once (reuse for all tests)
        amount_wei = str(round(AMOUNT_USDC * 1_000_000))
        payload = create_exact_evm_payment(
            chain_id=8453,  # Base mainnet
            token_address=USDC_ADDRESS,
            amount=amount_wei,
            to=WALLET_ADDRESS,
            from_address=account.address,
            private_key=private_key,
            rpc_url="https://mainnet.base.org",
        )

        print(f"[INFO] Payment payload created")
        print(f"       x402Version: {payload.get('x402Version')}")

        # Encode as PAYMENT-SIGNATURE header
        payload_json = json.dumps(payload, separators=(",", ":"))
        payment_header = base64.b64encode(payload_json.encode()).decode()

        results = []

        # Run tests
        async with httpx.AsyncClient(timeout=30.0) as client:
            for i, test_case in enumerate(TEST_CASES, 1):
                print(f"\n{test_case['name']}")
                print("-" * 80)

                # Prepare request
                headers = {
                    "Content-Type": "application/json",
                    "PAYMENT-SIGNATURE": payment_header,
                }

                # Make request
                try:
                    response = await client.post(
                        FULL_URL,
                        json=test_case["request"],
                        headers=headers,
                    )

                    status = response.status_code
                    print(f"HTTP Status: {status}")

                    if status == 200:
                        data = response.json()

                        # Print response
                        print(f"Sanitization Status: {data.get('sanitization_status')}")
                        print(f"Safe to Send: {data.get('safe_to_send_to_payment_metadata')}")
                        if data.get("detected_sensitive_fields"):
                            print(f"Detected Fields: {data['detected_sensitive_fields']}")
                        if data.get("recommended_next_step"):
                            print(f"Next Step: {data['recommended_next_step']}")

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
                        print("[ERROR] Payment Required - payment signature may be invalid")
                        result = {
                            "test": test_case["name"],
                            "status": status,
                            "passed": False,
                            "error": "Payment Required"
                        }
                        results.append(result)
                    else:
                        try:
                            error_data = response.json()
                            print(f"Error: {error_data}")
                        except:
                            print(f"Response: {response.text}")

                        result = {
                            "test": test_case["name"],
                            "status": status,
                            "passed": False,
                            "error": f"HTTP {status}"
                        }
                        results.append(result)

                except httpx.RequestError as e:
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
                print(f"     Detected: {result['detected_fields']}")
            print()

        # Overall result
        all_passed = all(r.get("passed") for r in results)
        print("-" * 80)
        if all_passed:
            print("[ALL TESTS PASSED]")
            return True
        else:
            print("[SOME TESTS FAILED]")
            return False

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(test_metadata_sanitizer())
    sys.exit(0 if result else 1)
