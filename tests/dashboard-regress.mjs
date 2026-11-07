// Round-2 regressions for index.html: scroll position under live events, and focus after clearing the rule chip.
// Usage: node tests/dashboard-regress.mjs index.html   (run from the repo root; needs playwright)
import { createRequire } from "module";
import fs from "fs";
const require = createRequire(process.cwd() + "/");
const { chromium } = require("playwright");
const HTML = fs.readFileSync(process.argv[2], "utf8");
const browser = await chromium.launch({ args: ["--no-sandbox"] });
let bad = 0;
const check = (name, ok, detail = "") => { if (!ok) bad++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : "  ->  " + detail}`); };
const ev = (i) => ({ ts: new Date(Date.UTC(2026, 10, 7, 20, 0, i)).toISOString(), event: "decision", decision: i % 2 ? "deny" : "ask",
  tool_name: "Read", rule: "r1", tool_use_id: "t" + i, session_id: "s1", step: i, input: { file_path: "/x" + i } });
const data = {
  events: Array.from({ length: 40 }, (_, i) => ev(i + 1)),
  status: { plugin_loaded: true, policy_loaded: true, policy_ok: true, log_found: true, isolation: false, step_cap: 200 },
  policy: { version: 1, rules: [{ id: "r1", decision: "deny", kind: "path", reason: "one", match: ["/x*"] }] },
};
async function open(live) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 700 } });
  const page = await ctx.newPage();
  await page.route("**/*", (r) => {
    const u = new URL(r.request().url());
    if (u.pathname === "/") return r.fulfill({ status: 200, contentType: "text/html", body: HTML });
    if (!live) return r.fulfill({ status: 404, body: "" });
    if (u.pathname === "/api/status") return r.fulfill({ json: data.status });
    if (u.pathname === "/api/policy") return r.fulfill({ json: data.policy });
    if (u.pathname === "/api/events") { const a = u.searchParams.get("after"); return r.fulfill({ json: a ? data.events.filter((e) => e.ts > a) : data.events }); }
    return r.fulfill({ status: 404, body: "" });
  });
  await page.goto("http://dash.test/");
  await page.waitForTimeout(1500);
  return { ctx, page };
}

{ // A: a scrolled feed does not slide when new events arrive
  const { ctx, page } = await open(true);
  const pos = () => page.evaluate(() => {
    const l = document.getElementById("events-list");
    const w = [...l.children].find((r) => r.textContent.includes("/x20"));
    return w ? Math.round(w.getBoundingClientRect().top) : null;
  });
  await page.evaluate(() => { document.getElementById("events-list").scrollTop = 300; });
  await page.waitForTimeout(300);
  const before = await pos();
  for (const i of [41, 42, 43]) data.events.push(ev(i));
  await page.waitForTimeout(2600);
  const after = await pos();
  check("a row being read stays in place while new events arrive", before !== null && after !== null && Math.abs(after - before) <= 1, `before ${before}, after ${after}`);
  await ctx.close();
}
{ // B: Enter on the rule chip's clear button keeps focus in the page and says so
  const { ctx, page } = await open(false);
  await page.locator(".rule-link-btn").first().focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);
  await page.locator(".active-rule-chip button").focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(400);
  const r = await page.evaluate(() => ({ tag: document.activeElement.tagName, id: document.activeElement.id, live: document.getElementById("live-status").textContent }));
  check("after clearing the rule chip, focus is not lost", r.tag !== "BODY", JSON.stringify(r));
  check("clearing the rule filter is announced", /cleared/i.test(r.live), r.live);
  await ctx.close();
}
await browser.close();
process.exit(bad ? 1 : 0);
