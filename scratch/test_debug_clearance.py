import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import asyncio
import httpx
from src.protected_app.app import app as protected_app
from src.waf_gateway.app import app as gateway_app, WAFGatewayApp
from src.firewall.policy import FirewallPolicy
from src.ml_service.model_loader import container
from src.ml_service.inference_engine import InferenceEngine
from src.waf_gateway.challenge import challenge_manager

if not container.is_ready:
    container.initialize()

engine = InferenceEngine(container)
gw = WAFGatewayApp(
    policy=FirewallPolicy(inspection_mode="blocking"),
    in_process_ml_engine=engine,
    in_process_upstream_app=protected_app,
)

async def test():
    await gw.initialize()
    import src.waf_gateway.app as gw_mod
    gw_mod.set_gateway(gw)
    client_ip = "127.0.0.1"
    ua = "TestUA"
    cookie = challenge_manager.issue_clearance_cookie(client_ip, ua)
    for probe in ["/admin", "/.env", "/config.php", "/phpmyadmin"]:
        gw.decision_engine.anomaly_detector.record_event(client_ip, probe, 404)

    transport = httpx.ASGITransport(app=gw_mod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://waf-gateway") as client:
        resp = await client.get("/api/items/1", headers={"User-Agent": ua, "Accept": "text/html", "Cookie": f"waf_clearance={cookie}"})
        print("Status with cookie:", resp.status_code)
        print("Headers with cookie:", resp.headers.get("X-WAF-Action"), resp.headers.get("X-WAF-Reason"))
        print("Body:", resp.text)
    await gw.shutdown()

asyncio.run(test())
