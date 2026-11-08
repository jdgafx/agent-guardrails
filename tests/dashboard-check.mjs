// Acceptance check for the agent-guardrails dashboard fixes.
// Usage: node agent-guardrails-dashboard-check.mjs <path-to-dashboard.html>
// Needs: playwright (chromium) and axe-core resolvable from the current folder.
//   npm i -D playwright axe-core && npx playwright install chromium
// Optional: CHROMIUM_PATH=/path/to/chrome to use a specific browser binary.
// Exit 0 = every check passed. Each failure prints one line.

import { createRequire } from "module";
import fs from "fs";
const require = createRequire(process.cwd() + "/");
const { chromium } = require("playwright");
const AXE = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

const file = process.argv[2];
if (!file) { console.error("usage: node check.mjs <dashboard.html>"); process.exit(2); }
const HTML = fs.readFileSync(file, "utf8");
const SECRET = "/x4-export-leak-marker";

const launchOpts = { args: ["--no-sandbox"] };
if (process.env.CHROMIUM_PATH) launchOpts.executablePath = process.env.CHROMIUM_PATH;
const browser = await chromium.launch(launchOpts);

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || !detail ? "" : "  ->  " + detail}`);
};

function liveData() {
  const events = [1, 2, 3, 4, 5].map((i) => ({
    ts: `2026-11-07T20:0${i}:00Z`, event: "decision",
    decision: i % 2 ? "deny" : "ask", tool_name: "Read", rule: "r1",
    tool_use_id: "t" + i, session_id: "s1", step: i,
    input: { file_path: i === 4 ? SECRET : "/x" + i },
  }));
  return {
    events,
    status: { plugin_loaded: true, policy_loaded: true, log_found: true, isolation: false, step_cap: 200 },
    policy: { version: 1, rules: [
      { id: "r1", decision: "deny", kind: "path", reason: "test rule one", match: ["/x*"] },
      { id: "r2", decision: "ask", kind: "command", reason: "test rule two", match: ["rm"] },
    ] },
  };
}

async function open({ width = 1440, height = 900, live = false, colorScheme = "dark", touch = false, data, qs = "" } = {}) {
  const ctx = await browser.newContext({
    viewport: { width, height }, colorScheme, hasTouch: touch, isMobile: touch, acceptDownloads: true,
  });
  const page = await ctx.newPage();
  const d = data || liveData();
  await page.route("**/*", (r) => {
    const u = new URL(r.request().url());
    if (u.pathname === "/") return r.fulfill({ status: 200, contentType: "text/html", body: HTML });
    if (!live) return r.fulfill({ status: 404, body: "" });
    if (u.pathname === "/api/status") return r.fulfill({ json: d.status });
    if (u.pathname === "/api/policy") return r.fulfill({ json: d.policy });
    if (u.pathname === "/api/events") {
      const after = u.searchParams.get("after");
      return r.fulfill({ json: after ? d.events.filter((e) => e.ts > after) : d.events });
    }
    return r.fulfill({ status: 404, body: "" });
  });
  await page.goto("http://dash.test/" + qs);
  await page.waitForTimeout(1500);
  return { ctx, page, data: d };
}

async function setTheme(page, theme) {
  const cur = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  if (cur !== theme) await page.click("#theme-toggle");
  await page.waitForTimeout(400); // let transitions finish
}

// 1. axe, both themes, a drawer open, desktop and phone
for (const [w, h] of [[1440, 900], [390, 844]]) {
  for (const theme of ["dark", "light"]) {
    const { ctx, page } = await open({ width: w, height: h });
    await setTheme(page, theme);
    const toggle = page.locator("[aria-expanded]").first();
    if (await toggle.count()) await toggle.click();
    await page.addScriptTag({ content: AXE });
    const v = await page.evaluate(async () =>
      (await axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] }))
        .violations.map((x) => `${x.id} (${x.nodes.length}) e.g. ${x.nodes[0].target.join(" ")}`));
    check(`axe: no WCAG 2.2 AA or best-practice violations, ${theme}, ${w}px`, v.length === 0, v.join("; "));
    await ctx.close();
  }
}

// 2. Non-text contrast of tokens (1.4.11), resolved through the browser
{
  const { ctx, page } = await open();
  for (const theme of ["dark", "light"]) {
    await setTheme(page, theme);
    const bad = await page.evaluate(() => {
      const probe = document.createElement("div"); document.body.appendChild(probe);
      const rgb = (v) => { probe.style.color = ""; probe.style.color = v; return getComputedStyle(probe).color.match(/[\d.]+/g).map(Number); };
      const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
      const lum = ([r, g, b]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
      const cr = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
      const tok = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
      const bgs = ["--bg-surface", "--bg-elevated", "--bg-canvas", "--bg-selected", "--bg-hover"];
      const ui = ["--border-control", "--border-focus", "--deny-solid", "--ask-solid", "--allow-solid", "--inj-solid"];
      const out = [];
      for (const f of ui) {
        if (!tok(f)) { out.push(`${f} missing`); continue; }
        for (const b of bgs) { const r = cr(rgb(tok(f)), rgb(tok(b))); if (r < 3) out.push(`${f} on ${b} ${r.toFixed(2)}`); }
      }
      for (const f of ["--text-primary", "--text-secondary", "--text-muted", "--accent-blue"]) {
        for (const b of bgs) { const r = cr(rgb(tok(f)), rgb(tok(b))); if (r < 4.5) out.push(`${f} on ${b} ${r.toFixed(2)}`); }
      }
      probe.remove(); return out;
    });
    check(`token contrast: text >= 4.5, controls and decision fills >= 3, ${theme}`, bad.length === 0, bad.join("; "));
  }
  await ctx.close();
}

// 3. No sideways scroll on phones, both themes
for (const w of [390, 360]) {
  const { ctx, page } = await open({ width: w, height: 800 });
  const sw = await page.evaluate(() => document.documentElement.scrollWidth);
  check(`no horizontal scroll at ${w}px`, sw <= w, `scrollWidth ${sw}`);
  await ctx.close();
}

// 4. Live refresh keeps keyboard focus and open drawers
{
  const { ctx, page, data } = await open({ live: true });
  const rule = page.locator('[data-rule-id="r2"]').first();
  await rule.focus();
  await page.waitForTimeout(2600);
  const still = await page.evaluate(() => document.activeElement && document.activeElement.closest('[data-rule-id="r2"]') !== null);
  check("focus on a rule survives a live poll", still);

  const toggles = page.locator(".events-list [aria-expanded]");
  await toggles.nth(1).click();
  const before = await page.locator('.events-list [aria-expanded="true"]').count();
  data.events.push({ ts: "2026-11-07T20:09:00Z", event: "decision", decision: "allow", tool_name: "Read",
    rule: "r2", tool_use_id: "t6", session_id: "s1", step: 6, input: { file_path: "/x6" } });
  await page.waitForTimeout(2600);
  const openText = await page.evaluate(() => {
    const t = document.querySelector('.events-list [aria-expanded="true"]');
    if (!t) return "";
    const panel = document.getElementById(t.getAttribute("aria-controls") || "");
    return panel ? panel.textContent : "";
  });
  check("an open event drawer stays open, on the same event, when a new event arrives",
    before === 1 && openText.includes("t4"), `open drawer text: ${openText.slice(0, 80)}`);
  await ctx.close();
}

// 5. Rule link inside an event works from the keyboard and does not toggle the drawer
{
  const { ctx, page } = await open();
  const link = page.locator(".rule-link-btn").first();
  const id = (await link.textContent()).trim();
  const ownToggle = await link.evaluate((el) => {
    const item = el.closest('[role="listitem"], li');
    const t = item && item.querySelector("[aria-expanded]");
    return t ? t.getAttribute("aria-expanded") : null;
  });
  await link.focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);
  const after = await page.evaluate(() => document.getElementById("filter-rule").value);
  const toggled = await page.evaluate(() => document.querySelectorAll('.events-list [aria-expanded="true"]').length);
  check("Enter on a rule link filters by that rule and opens no drawer",
    after === id && ownToggle === "false" && toggled === 0, `filter=${after}, drawers open=${toggled}`);
  await ctx.close();
}

// 6. Focus ring is not clipped by a scrolling list
{
  const { ctx, page } = await open();
  const clipped = await page.evaluate(() => {
    const out = [];
    const targets = [document.querySelector(".rule-row, .rules-list button"), document.querySelector(".events-list [aria-expanded]")];
    for (const el of targets) {
      if (!el) { out.push("target missing"); continue; }
      el.focus({ preventScroll: false });
      const cs = getComputedStyle(el);
      const ext = parseFloat(cs.outlineOffset) + parseFloat(cs.outlineWidth);
      let sc = el.parentElement;
      while (sc && !/(auto|scroll|hidden)/.test(getComputedStyle(sc).overflowY + getComputedStyle(sc).overflowX)) sc = sc.parentElement;
      if (!sc) continue;
      const r = el.getBoundingClientRect(), c = sc.getBoundingClientRect();
      if (cs.outlineStyle === "none" && cs.boxShadow === "none") out.push(`${el.className}: no focus indicator`);
      else if (r.left - ext < c.left - 0.5 || r.right + ext > c.right + 0.5) out.push(`${el.className}: ring clipped by ${sc.className}`);
    }
    return out;
  });
  check("focus ring on rule rows and event toggles is fully visible", clipped.length === 0, clipped.join("; "));
  await ctx.close();
}

// 7. Target sizes: >= 24px everywhere, >= 44px on touch phones
for (const [touch, min, w] of [[false, 24, 1440], [true, 44, 390]]) {
  const { ctx, page } = await open({ width: w, height: 844, touch });
  const small = await page.evaluate((min) => [...document.querySelectorAll("button, select, a[href], [role=button], [tabindex]")]
    .filter((e) => e.offsetParent && e.getAttribute("tabindex") !== "-1")
    .map((e) => { const r = e.getBoundingClientRect(); return { c: (e.className || e.tagName).toString().split(" ")[0], h: Math.round(r.height), w: Math.round(r.width) }; })
    .filter((x) => x.h < min || x.w < min)
    .map((x) => `${x.c} ${x.w}x${x.h}`), min);
  const uniq = [...new Set(small)];
  check(`interactive targets >= ${min}px ${touch ? "on touch" : "with a mouse"}`, uniq.length === 0, uniq.slice(0, 6).join(", "));
  await ctx.close();
}

// 8. Theme follows the OS on first visit and remembers the choice
{
  const { ctx, page } = await open({ colorScheme: "light" });
  const first = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  await page.click("#theme-toggle");
  await page.waitForTimeout(200);
  const chosen = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  await page.reload(); await page.waitForTimeout(1200);
  const again = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  check("theme starts from the OS setting and the user's choice survives a reload",
    first === "light" && chosen === "dark" && again === "dark", `first=${first} chosen=${chosen} reload=${again}`);
  await ctx.close();
}

// 9. Download exports the clean page, never the live audit log
{
  const { ctx, page } = await open({ live: true });
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#download-html-btn")]);
  const text = fs.readFileSync(await dl.path(), "utf8");
  check("downloaded index.html holds no live event data", !text.includes(SECRET) && !text.includes("event-item"),
    text.includes(SECRET) ? "export contains a live event's file path" : "export contains rendered event rows");
  await ctx.close();
}

// 10. Decision pills show and announce their filter state
{
  const { ctx, page } = await open();
  const pill = page.locator(".telemetry-pill.deny-pill");
  const a = await pill.getAttribute("aria-pressed");
  await pill.click(); await page.waitForTimeout(200);
  const b = await page.locator(".telemetry-pill.deny-pill").getAttribute("aria-pressed");
  check("Deny pill toggles aria-pressed false -> true", a === "false" && b === "true", `before=${a} after=${b}`);
  await ctx.close();
}

// 11. Last Event tile never shows green when the newest event carried an injection warning
{
  const d = liveData();
  d.events.push({ ts: "2026-11-07T20:09:30Z", event: "result", decision: "allow", tool_name: "WebFetch",
    rule: null, tool_use_id: "t9", session_id: "s1", step: 9, input: { url: "https://example.com" },
    warnings: [{ marker: "ignore-previous", excerpt: "ignore previous instructions" }] });
  const { ctx, page } = await open({ live: true, data: d });
  const cls = await page.getAttribute("#tile-last", "class");
  const txt = await page.textContent("#tile-last");
  check("Last Event tile flags an injection warning (not tone-ok, says injection)",
    !/tone-ok/.test(cls) && /injection/i.test(txt), `class="${cls}"`);
  await ctx.close();
}

// 12. Smallest rendered text is 12px or larger
{
  const { ctx, page } = await open();
  const tiny = await page.evaluate(() => {
    const out = new Set();
    document.querySelectorAll("body *").forEach((e) => {
      if (!e.offsetParent) return;
      if (![...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) return;
      const fs = parseFloat(getComputedStyle(e).fontSize);
      if (fs < 12) out.add(`${(e.className || e.tagName).toString().split(" ")[0]} ${fs}px`);
    });
    return [...out];
  });
  check("no visible text smaller than 12px", tiny.length === 0, tiny.slice(0, 8).join(", "));
  await ctx.close();
}

// 13. Sample mode and every preview state render with no script errors
{
  const errs = [];
  const { ctx, page } = await open({ qs: "?states=1" });
  page.on("pageerror", (e) => errs.push(e.message));
  const n = await page.locator(".state-btn").count();
  for (let i = 0; i < n; i++) { await page.locator(".state-btn").nth(i).click(); await page.waitForTimeout(150); }
  check("every ?states=1 preview state renders with no script errors", n > 0 && errs.length === 0, `states=${n} errors=${errs.slice(0, 3).join(" | ")}`);
  await ctx.close();
}

// 14. T-033: the sample rows as the viewer sees them: the marked session shows its labels, an old line shows neither
{
  const { ctx, page } = await open();
  const rows = await page.evaluate(() => [...document.querySelectorAll("#events-list > li.event-entry")].map((li) => ({
    tool: (li.querySelector(".event-tool-pill") || {}).textContent,
    chip: (li.querySelector(".decision-badge") || {}).textContent,
    note: (li.querySelector(".row-note") || {}).textContent || null,
    rule: (li.querySelector(".event-rule-cell") || {}).textContent.trim(),
    inj: !!li.querySelector(".injection-flag"),
    text: li.innerText,
  })));
  const marked = rows.find((r) => r.tool === "WebFetch" && r.note && r.note.includes("session marked"));
  check("sample WebFetch row of the marked session: Flagged, injection badge, 'warned Claude' and 'session marked'",
    !!marked && marked.chip === "Flagged" && marked.inj && marked.note === "warned Claude \u00b7 session marked", JSON.stringify(marked));
  const asked = rows.find((r) => r.tool === "mcp__github__create_issue" && r.chip === "Ask");
  check("sample ask-after-injection row shows Ask and that rule", !!asked && asked.rule === "ask-after-injection", JSON.stringify(asked));
  const old = rows.find((r) => r.tool === "WebFetch" && r.inj && r !== marked);
  check("an old line (warnings, no warned field) shows 'logged only' and neither 'warned Claude' nor 'session marked'",
    !!old && old.note === "logged only" && !/warned Claude|session marked/.test(old.text), JSON.stringify(old));
  await ctx.close();
}

await browser.close();
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed} of ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
