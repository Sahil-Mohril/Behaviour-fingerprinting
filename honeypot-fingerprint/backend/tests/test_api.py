import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        for _ in range(100):
            if c.get("/api/sources").json()["status"] == "ready":
                break
            time.sleep(0.1)
        yield c


def _wait_finished(client, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = client.get("/api/replay/status").json()
        if st["state"] == "finished":
            return st
        time.sleep(0.2)
    raise AssertionError("replay did not finish")


def test_health_docs_and_sources(client):
    assert client.get("/api/health").json() == {"ok": True}
    assert client.get("/openapi.json").status_code == 200
    src = client.get("/api/sources").json()
    assert {s["adapter"] for s in src["sources"]} >= {"cicflow", "cowrie", "opencanary", "zeek"}
    beh = client.get("/api/behaviours").json()
    assert any(b["key"] == "icmp_flood" and b["data_source"] == "no data source" for b in beh)


def test_returning_replay_end_to_end(client):
    src = client.get("/api/sources").json()["sources"]
    cic = [s for s in src if s["name"] == "cicids2017_sample.csv"][0]
    client.put("/api/settings", json={"rule_mode": "auto"})
    r = client.post("/api/replay/returning", json={"source_id": cic["id"], "label": "SSH-Patator", "speed": 400,
                                                   "reset_learning": True})
    assert r.status_code == 200, r.text
    _wait_finished(client)
    fps = client.get("/api/fingerprints").json()
    assert any(f["category"] == "ssh_bruteforce" and f["returning"] for f in fps)
    fid = [f for f in fps if f["category"] == "ssh_bruteforce"][0]["id"]
    detail = client.get(f"/api/fingerprints/{fid}").json()
    assert detail["radar"] and detail["importance"] and detail["traits"] and len(detail["episodes"]) >= 2
    alerts = client.get("/api/alerts", params={"type": "returning"}).json()
    assert alerts and alerts[0]["breakdown"]["score"] >= 0.85 and alerts[0]["explanation"]
    rules = client.get("/api/rules", params={"status": "active"}).json()
    assert rules
    exp = client.get("/api/rules/export", params={"format": "nftables"})
    assert exp.status_code == 200 and "attachment" in exp.headers["content-disposition"] and "drop" in exp.text
    ev = client.get("/api/metrics/evaluation").json()
    assert ev["returning"]["rate"] == 1.0 and "online" in ev
    ov = client.get("/api/metrics/overview").json()
    assert ov["kpis"]["dropped"] > 0 and ov["series"]
    proj = client.get("/api/fingerprints/projection", params={"method": "pca"}).json()
    assert proj["points"] and proj["centroids"]
    ids = ",".join(f["id"] for f in fps[:2])
    cmp = client.get("/api/fingerprints/compare", params={"ids": ids}).json()
    assert len(cmp["pairs"]) == 1 and 0 <= cmp["pairs"][0]["combined"] <= 1
    evs = client.get("/api/events", params={"size": 5}).json()
    assert evs["items"]


def test_user_actions(client):
    fps = client.get("/api/fingerprints").json()
    fid = fps[0]["id"]
    assert client.patch(f"/api/fingerprints/{fid}", json={"name": "Renamed"}).json()["name"] == "Renamed"
    alerts = client.get("/api/alerts").json()
    a = client.post(f"/api/alerts/{alerts[0]['id']}/ack").json()
    assert a["status"] == "acknowledged"
    sug = client.get("/api/rules", params={"status": "suggested"}).json()
    if sug:
        assert client.post(f"/api/rules/{sug[0]['id']}/reject").json()["status"] == "rejected"
    assert client.post("/api/allowlist", json={"cidr": "203.0.113.0/24", "note": "test"}).status_code == 200
    assert any(e["cidr"] == "203.0.113.0/24" for e in client.get("/api/allowlist").json())
    assert client.post("/api/allowlist", json={"cidr": "not-an-ip"}).status_code == 400
    s = client.put("/api/settings", json={"similarity_threshold": 0.9, "weight_numeric": 0.7}).json()
    assert s["settings"]["similarity_threshold"] == 0.9 and "weight_numeric" in s["changed"]
    client.put("/api/settings", json={"similarity_threshold": 0.85, "weight_numeric": 0.6, "rule_mode": "suggest"})


def test_websocket_streams_batched_ticks(client):
    with client.websocket_connect("/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        tick = ws.receive_json()
        assert tick["type"] == "tick" and "kpis" in tick and isinstance(tick["events"], list)


def test_demo_endpoint_and_controls(client):
    r = client.post("/api/replay/demo", params={"speed": 50})
    assert r.status_code == 200 and r.json()["plan"]["mode"] == "demo"
    assert client.post("/api/replay/pause").json()["state"] == "paused"
    assert client.post("/api/replay/resume").json()["state"] == "running"
    assert client.post("/api/replay/speed", json={"speed": 100}).json()["speed"] == 100
    assert client.post("/api/replay/stop").json()["state"] == "finished"
    assert client.post("/api/reset").json() == {"ok": True}
