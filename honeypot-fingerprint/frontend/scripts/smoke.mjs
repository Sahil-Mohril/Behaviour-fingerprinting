// Smoke test for the production build: the bundle exists, references its assets and contains every page.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const fail = (m) => { console.error("SMOKE FAIL:", m); process.exit(1); };

if (!existsSync(join(dist, "index.html"))) fail("dist/index.html missing");
const html = readFileSync(join(dist, "index.html"), "utf8");
const assets = readdirSync(join(dist, "assets"));
const js = assets.filter((f) => f.endsWith(".js"));
const css = assets.filter((f) => f.endsWith(".css"));
if (!js.length || !css.length) fail("missing JS or CSS bundle");
for (const f of [...js, ...css]) if (!html.includes(f)) fail(`index.html does not reference ${f}`);
const bundle = js.map((f) => readFileSync(join(dist, "assets", f), "utf8")).join("\n");
for (const marker of ["Replay Control", "Live Overview", "Fingerprint Explorer", "Firewall Rules", "Evaluation", "Settings", "/ws"]) {
  if (!bundle.includes(marker)) fail(`bundle lacks "${marker}"`);
}
console.log(`smoke ok: ${js.length} js, ${css.length} css, ${(bundle.length / 1024).toFixed(0)} KiB js`);
