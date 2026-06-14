import sys, os, types, json, warnings
sys.path.insert(0, '.')
os.environ['TEST_MODE'] = 'false'
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
client = TestClient(app, raise_server_exceptions=True)

PASS = "[PASS]"
FAIL = "[FAIL]"

# Check /llms.txt error detail
print("=== /llms.txt error detail ===")
client2 = TestClient(app, raise_server_exceptions=False)
r = client2.get('/llms.txt')
print(f"  HTTP {r.status_code}: {r.text[:200]}")

# Check by reading file directly
print("\n=== Direct file read (encoding check) ===")
try:
    with open('llms.txt', encoding='utf-8') as f:
        content = f.read()
    print(f"  llms.txt UTF-8 read OK, len={len(content)}")
    print(f"  metadata-sanitize present: {'metadata-sanitize' in content}")
    print(f"  Live API present: {'Live API' in content}")
except Exception as e:
    print(f"  UTF-8 read error: {e}")

try:
    with open('skill.md', encoding='utf-8') as f:
        content = f.read()
    print(f"  skill.md UTF-8 read OK, len={len(content)}")
    print(f"  metadata-sanitize present: {'metadata-sanitize' in content}")
except Exception as e:
    print(f"  skill.md UTF-8 read error: {e}")

# x402.json - check for metadata-sanitize in all endpoints
print("\n=== /.well-known/x402.json full check ===")
r = client2.get('/.well-known/x402.json')
d = r.json()
endpoints = d.get("endpoints", d.get("resources", []))
print(f"  total entries: {len(endpoints)}")
found_ms = False
for ep in endpoints:
    path = ep.get("path", ep.get("url", ""))
    if "metadata-sanitize" in path:
        found_ms = True
        print(f"  {PASS} metadata-sanitize found: {path} price={ep.get('price')} method={ep.get('method')}")
        break
if not found_ms:
    print(f"  {FAIL} metadata-sanitize NOT found in endpoints/resources")
    print(f"  Existing paths: {[ep.get('path', ep.get('url', '')) for ep in endpoints]}")

# Also check /.well-known/x402 (manifest)
print("\n=== GET /.well-known/x402 (manifest) ===")
r = client2.get('/.well-known/x402')
print(f"  HTTP {r.status_code}")
if r.status_code == 200:
    d = r.json()
    resources = d.get("resources", [])
    print(f"  resources count: {len(resources)}")
    found_ms2 = any("metadata-sanitize" in str(res) for res in resources)
    print(f"  {PASS if found_ms2 else FAIL} metadata-sanitize in manifest resources: {found_ms2}")
    if found_ms2:
        for res in resources:
            if "metadata-sanitize" in str(res):
                print(f"    => {res}")

# Check scan 402 response for resource field
print("\n=== Existing /api/security/scan 402 resource field ===")
r = client2.post('/api/security/scan', json={"content": "test"})
if r.status_code == 402:
    d = r.json()
    accepts = d.get("accepts", [])
    a0 = accepts[0] if accepts else {}
    print(f"  resource field: {a0.get('resource', 'not present')}")
