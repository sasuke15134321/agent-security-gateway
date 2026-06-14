import sys, os, types, json, warnings
sys.path.insert(0, '.')
os.environ.setdefault('TEST_MODE', 'true')
os.environ.setdefault('DATABASE_URL', 'postgresql://dummy:dummy@localhost/dummy')
os.environ.setdefault('WALLET_ADDRESS', '0x60c402878EfcEcAe5733A88075328Aa2320C39BE')
os.environ.setdefault('ANTHROPIC_API_KEY', 'sk-ant-dummy-key')

import httpx
_orig = httpx.AsyncClient.__init__
def _patched(self, *a, **kw):
    kw.pop('proxies', None)
    _orig(self, *a, **kw)
httpx.AsyncClient.__init__ = _patched

mcp_mod = types.ModuleType('mcp')
mcp_server_mod = types.ModuleType('mcp.server')
mcp_fastmcp_mod = types.ModuleType('mcp.server.fastmcp')
class FastMCP:
    def __init__(self, *a, **kw): pass
    def tool(self, *a, **kw):
        def dec(f): return f
        return dec
    def streamable_http_app(self): return None
mcp_fastmcp_mod.FastMCP = FastMCP
sys.modules['mcp'] = mcp_mod
sys.modules['mcp.server'] = mcp_server_mod
sys.modules['mcp.server.fastmcp'] = mcp_fastmcp_mod

warnings.filterwarnings('ignore')
from fastapi.testclient import TestClient
from main import app
client = TestClient(app, raise_server_exceptions=False)

PASS = "[PASS]"
FAIL = "[FAIL]"

# ---- 3. GET /health ----
print("=== 3. GET /health ===")
r = client.get('/health')
ok = r.status_code == 200
print(f"  {PASS if ok else FAIL} HTTP {r.status_code}")

# ---- GET / ----
print("\n=== GET / (root) ===")
r = client.get('/')
d = r.json()
ep = d.get('endpoints', {})
pricing = d.get('pricing', {})
in_ep = "metadata_sanitize" in ep
in_pr = "metadata_sanitize" in pricing
print(f"  {PASS if in_ep else FAIL} metadata_sanitize in endpoints: {in_ep} => {ep.get('metadata_sanitize')}")
print(f"  {PASS if in_pr else FAIL} metadata_sanitize in pricing: {in_pr} => {pricing.get('metadata_sanitize')}")

# ---- 4. Unpaid POST /api/security/metadata-sanitize -> 402 ----
print("\n=== 4. 未払い POST /api/security/metadata-sanitize ===")
payload = {
    "payment_protocol": "x402",
    "metadata_payload": {
        "purpose": "AI API usage fee",
        "resource": "metadata_sanitize_test",
        "amount": "0.05 USDC"
    },
    "context_type": "payment_metadata",
    "payment_purpose": "AI API usage fee"
}
r = client.post('/api/security/metadata-sanitize', json=payload)
print(f"  HTTP status: {r.status_code} (expect 402)")
if r.status_code == 402:
    d = r.json()
    ver = d.get("x402Version")
    accepts = d.get("accepts", [])
    a0 = accepts[0] if accepts else {}
    amount = a0.get("amount")
    network = a0.get("network")
    payto = a0.get("payTo")
    asset = a0.get("asset")
    resource = a0.get("resource", {})
    pmt_hdr = "PAYMENT-REQUIRED" in r.headers

    print(f"  {PASS if ver == 2 else FAIL} x402Version: {ver} (expect 2)")
    print(f"  {PASS if amount == '50000' else FAIL} amount: {amount} (expect 50000)")
    print(f"  {PASS if network == 'eip155:8453' else FAIL} network: {network}")
    print(f"  {PASS if payto else FAIL} payTo: {payto}")
    print(f"  {PASS if asset else FAIL} asset: {asset}")
    print(f"  {PASS if pmt_hdr else FAIL} PAYMENT-REQUIRED header: {pmt_hdr}")
    print(f"  resource in accepts[0]: {resource}")
else:
    print(f"  {FAIL} Unexpected: {r.text[:300]}")

# ---- 5. GET /openapi.json ----
print("\n=== 5. GET /openapi.json ===")
r = client.get('/openapi.json')
schema = r.json()
paths = schema.get("paths", {})
ep_path = "/api/security/metadata-sanitize"
has_ep = ep_path in paths
print(f"  {PASS if has_ep else FAIL} {ep_path} in paths: {has_ep}")
if has_ep:
    ep_info = paths[ep_path]
    post_info = ep_info.get("post", {})
    has_req = "requestBody" in post_info
    has_resp = "200" in post_info.get("responses", {})
    x_pay = post_info.get("x-payment-info") or post_info.get("openapi_extra")
    # Check x402 price in openapi_extra
    extra = post_info
    price_ok = False
    if "x-payment-info" in extra:
        pi = extra["x-payment-info"]
        price_ok = str(pi.get("price", "")) == "0.05"
    print(f"  {PASS if has_req else FAIL} requestBody present: {has_req}")
    print(f"  {PASS if has_resp else FAIL} response 200 present: {has_resp}")
    print(f"  x-payment-info: {extra.get('x-payment-info', 'not found')}")
    # Check for safe_to_send_to_payment_metadata in schema
    schemas = schema.get("components", {}).get("schemas", {})
    stspm_found = any("safe_to_send_to_payment_metadata" in str(v) for v in schemas.values())
    print(f"  {PASS if stspm_found else FAIL} safe_to_send_to_payment_metadata in schemas: {stspm_found}")

# ---- 6. GET /.well-known/x402.json ----
print("\n=== 6. GET /.well-known/x402.json ===")
r = client.get('/.well-known/x402.json')
x402 = r.json()
resources = x402.get("resources", [])
ep_urls = [res.get("url","") + res.get("path","") for res in resources]
# check if metadata-sanitize is in resources
found_ms = any("metadata-sanitize" in str(res) for res in resources)
print(f"  {PASS if found_ms else FAIL} metadata-sanitize in resources: {found_ms}")
for res in resources:
    path = res.get("url", res.get("path", ""))
    price = res.get("price", res.get("amount", ""))
    method = res.get("method", "")
    if "metadata-sanitize" in str(res):
        print(f"    => path: {path}, price: {price}, method: {method}")
# check existing resources not removed
print(f"  total resources: {len(resources)} (expect >= old count + 1)")

# ---- 7. docs: llms.txt, skill.md ----
print("\n=== 7. llms.txt / skill.md ===")
r = client.get('/llms.txt')
llms_ok = "metadata-sanitize" in r.text and "Live API" in r.text and "planned" not in r.text.lower()
print(f"  {PASS if 'metadata-sanitize' in r.text else FAIL} metadata-sanitize in llms.txt")
print(f"  {PASS if 'Live API' in r.text else FAIL} 'Live API' in llms.txt")
print(f"  {PASS if 'planned' not in r.text.lower() else FAIL} no 'planned' in llms.txt")

r = client.get('/skill.md')
skill_ok = "metadata-sanitize" in r.text
print(f"  {PASS if skill_ok else FAIL} metadata-sanitize in skill.md")
print(f"  {PASS if 'planned' not in r.text.lower() else FAIL} no 'planned' in skill.md")

# ---- 8. metadata content non-storage check ----
print("\n=== 8. metadata本文非保存 (code check) ===")
with open('main.py', encoding='utf-8') as f:
    main_src = f.read()
# Check for metadata_payload being saved to DB
import re
# Find the sanitize_metadata handler
handler_match = re.search(r'async def sanitize_metadata.*?(?=\n@app|\nclass |\Z)', main_src, re.DOTALL)
if handler_match:
    handler = handler_match.group(0)
    stores_payload = 'metadata_payload' in handler and 'log_scan_result' in handler
    stores_hash_only = 'content_hash' in handler and 'metadata_payload' not in handler.replace('request.metadata_payload', '').replace('metadata_payload=', 'REMOVED=')
    # Check that metadata_payload content is not directly in threats_detected
    direct_store = re.search(r'log_scan_result.*?metadata_payload', handler, re.DOTALL)
    print(f"  handler found: yes ({len(handler)} chars)")
    print(f"  {PASS if 'content_hash' in handler else FAIL} content_hash used in DB log")
    print(f"  {PASS if direct_store is None else FAIL} metadata_payload NOT directly passed to log_scan_result")
    # Check print/logger with metadata_payload
    log_leak = re.search(r'(print|logger\.\w+)\s*\([^)]*metadata_payload', handler)
    print(f"  {PASS if log_leak is None else FAIL} no direct metadata_payload in print/logger")
else:
    print(f"  {FAIL} sanitize_metadata handler not found in main.py")

# ---- 9. Existing endpoint regression ----
print("\n=== 9. 既存エンドポイント退行確認 ===")
r = client.post('/api/security/scan', json={"content": "test", "content_type": "text"})
print(f"  {PASS if r.status_code == 402 else FAIL} POST /api/security/scan: {r.status_code} (expect 402)")

r2 = client.get('/health')
print(f"  {PASS if r2.status_code == 200 else FAIL} GET /health: {r2.status_code} (expect 200)")

print("\n=== DONE ===")
