import sys, os, types, json, warnings
sys.path.insert(0, '.')
os.environ['TEST_MODE'] = 'false'  # disable TEST_MODE to check real 402 flow
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

# ---- 4. Unpaid 402 test (TEST_MODE=false) ----
print("=== 4. 未払い POST /api/security/metadata-sanitize (TEST_MODE=false) ===")
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
    print(f"  resource: {resource}")
else:
    print(f"  {FAIL} Unexpected: {r.text[:400]}")

# ---- 4b. Unpaid POST /api/security/scan -> 402 ----
print("\n=== 9. POST /api/security/scan -> 402 (TEST_MODE=false) ===")
r = client.post('/api/security/scan', json={"content": "test", "content_type": "text"})
print(f"  {PASS if r.status_code == 402 else FAIL} HTTP {r.status_code} (expect 402)")
if r.status_code == 402:
    d = r.json()
    print(f"  x402Version: {d.get('x402Version')}, amount: {d.get('accepts', [{}])[0].get('amount')}")

# ---- Debug: /.well-known/x402.json full response ----
print("\n=== 6. GET /.well-known/x402.json (full debug) ===")
r = client.get('/.well-known/x402.json')
print(f"  HTTP {r.status_code}")
try:
    d = r.json()
    print(f"  Full response: {json.dumps(d, indent=2)[:2000]}")
except:
    print(f"  Raw: {r.text[:500]}")

# ---- Debug: llms.txt ----
print("\n=== 7a. GET /llms.txt (first 500 chars) ===")
r = client.get('/llms.txt')
print(f"  HTTP {r.status_code}")
print(f"  First 500: {r.text[:500]}")
print(f"  'metadata-sanitize' in body: {'metadata-sanitize' in r.text}")
print(f"  'Live API' in body: {'Live API' in r.text}")

# ---- Debug: skill.md ----
print("\n=== 7b. GET /skill.md (contains check) ===")
r = client.get('/skill.md')
print(f"  HTTP {r.status_code}")
print(f"  'metadata-sanitize' in body: {'metadata-sanitize' in r.text}")
print(f"  First 300: {r.text[:300]}")
