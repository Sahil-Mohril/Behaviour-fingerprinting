"""Drive the running web app (http://localhost:5173), replay the demo and the mixed run through its API,
then save full-page screenshots and the evaluation JSON the Evaluation page shows.

    python capture_site.py <paper_dir>      (needs: pip install playwright; a Chromium/Edge browser)
"""
import json, sys, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = "http://localhost:5173"
out = Path(sys.argv[1]); (out / "figures").mkdir(exist_ok=True); (out / "results").mkdir(exist_ok=True)


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"null")


def wait_finished():
    while call("GET", "/api/replay/status")["state"] not in ("finished", "idle", "stopped"):
        time.sleep(1)


def shoot(pg, path, name, wait=2500, click=None):
    pg.goto(BASE + path); pg.wait_for_timeout(wait)
    if click:
        pg.get_by_text(click).first.click(); pg.wait_for_timeout(700)
    pg.screenshot(path=str(out / "figures" / f"{name}.png"))


def panel(pg, title, name):
    """Screenshot one card (section.card) found by its header text."""
    pg.get_by_text(title).first.locator("xpath=ancestor::section[1]").screenshot(path=str(out / "figures" / f"{name}.png"))


sid = {s["name"]: s["id"] for s in call("GET", "/api/sources")["sources"]}
MIXED = [
    dict(source_id=sid["cicids2017_sample.csv"], labels=["BENIGN"], repeat=80, repeat_new_ips=True, compress=7000),
    dict(source_id=sid["cicids2017_sample.csv"], labels=["SSH-Patator"], repeat=8, offset=30, compress=20),
    dict(source_id=sid["cicddos2019_sample.csv"], labels=["Syn"], repeat=200, offset=90, compress=1, remap_ips=True),
    dict(source_id=sid["cicddos2019_sample.csv"], labels=["DrDoS_DNS"], repeat=150, offset=40, compress=1),
    dict(source_id=sid["zeek_conn_labeled.log"], labels=["C&C-HeartBeat"], repeat=12, offset=20, compress=1),
    dict(source_id=sid["zeek_conn_labeled.log"], labels=["PartOfAHorizontalPortScan"], repeat=10, offset=150,
         compress=3, remap_ips=True),
    dict(source_id=sid["cowrie_sample.json"], repeat=6, offset=130, compress=6, label_override="ssh_bruteforce"),
    dict(source_id=sid["opencanary_sample.json"], repeat=6, offset=120, compress=4),
]

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge", headless=True)
    pg = b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    # light theme prints better; the app reads its theme from localStorage
    pg.add_init_script("try { localStorage.setItem('hfp-theme', 'light') } catch (e) {}")
    # --- scenario 1: deterministic demo (returning attacker) ---
    call("POST", "/api/reset")
    call("POST", "/api/replay/demo?speed=10")
    shoot(pg, "/", "web_replay_running", wait=6000)
    wait_finished()
    json.dump(call("GET", "/api/metrics/evaluation"), open(out / "results/web_demo_eval.json", "w"), indent=1)
    json.dump(call("GET", "/api/metrics/overview"), open(out / "results/web_demo_overview.json", "w"), indent=1)
    json.dump(call("GET", "/api/alerts"), open(out / "results/web_demo_alerts.json", "w"), indent=1)
    json.dump(call("GET", "/api/rules"), open(out / "results/web_demo_rules.json", "w"), indent=1)
    shoot(pg, "/overview", "web_overview")
    shoot(pg, "/fingerprints", "web_fingerprints", wait=3500)
    shoot(pg, "/alerts", "web_alerts", click="Returning behaviour:")
    shoot(pg, "/rules", "web_rules")
    shoot(pg, "/evaluation", "web_demo_evaluation")
    panel(pg, "Confusion matrix:", "web_demo_cm_online")
    pg.get_by_text("After clustering").first.click(); pg.wait_for_timeout(800)
    panel(pg, "Confusion matrix:", "web_demo_cm_final")
    # --- scenario 2: mixed labelled replay (confusion matrix) ---
    call("POST", "/api/reset")
    call("POST", "/api/replay/custom", dict(name="Mixed labelled replay", selections=MIXED, speed=100, reset_learning=True))
    wait_finished()
    time.sleep(3)
    json.dump(call("GET", "/api/metrics/evaluation"), open(out / "results/web_mixed_eval.json", "w"), indent=1)
    json.dump(call("GET", "/api/metrics/overview"), open(out / "results/web_mixed_overview.json", "w"), indent=1)
    json.dump(call("GET", "/api/fingerprints"), open(out / "results/web_mixed_fingerprints.json", "w"), indent=1)
    shoot(pg, "/evaluation", "web_mixed_evaluation_online")
    panel(pg, "Confusion matrix:", "web_mixed_cm_online")
    panel(pg, "Per-behaviour scores", "web_mixed_perclass_online")
    pg.get_by_text("After clustering").first.click(); pg.wait_for_timeout(800)
    pg.screenshot(path=str(out / "figures/web_mixed_evaluation_final.png"))
    panel(pg, "Confusion matrix:", "web_mixed_cm_final")
    panel(pg, "Ground-truth campaigns", "web_mixed_campaigns")
    shoot(pg, "/fingerprints", "web_mixed_fingerprints", wait=3500)
    shoot(pg, "/overview", "web_mixed_overview")
    shoot(pg, "/rules", "web_mixed_rules")
    b.close()
print("done")
