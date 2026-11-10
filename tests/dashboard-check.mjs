// Acceptance check for the dashboard page: accessibility, contrast, sizes, focus, and text-only handling of log strings.
// It runs the page against the real server on real log files. Nothing is mocked.
// Usage: node tests/dashboard-check.mjs index.html   (run from the repo root; needs playwright, axe-core and python3)
// Exit 0 = every check passed. Each failure prints one line.
import fs from "fs";
import path from "path";
import { AXE, REPO, appendLine, browser, check, detail, failures, folder, home, line, mark, mode, open, rowCount, startServer, stop } from "./dashboard-server.mjs";

const HOME = home();
const base = folder("base");
for (const i of [1, 2, 3, 4, 5]) appendLine(base, line(i));
const srv = await startServer(base, { env: { HOME } });
const theme = (page) => page.evaluate(() => document.documentElement.getAttribute("data-theme"));
async function setTheme(page, want) {
  if ((await theme(page)) !== want) await page.click("#theme-toggle");
  await page.waitForTimeout(300); // let transitions finish
}

// 1. axe, both themes, a row open, desktop and phone
for (const [w, h] of [[1440, 900], [390, 844]]) {
  for (const t of ["dark", "light"]) {
    const { ctx, page } = await open(srv.link, { width: w, height: h });
    await setTheme(page, t);
    await page.locator(".row-toggle").first().click();
    await page.addScriptTag({ content: AXE });
    const v = await page.evaluate(async () =>
      (await axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] }))
        .violations.map((x) => `${x.id} (${x.nodes.length}) e.g. ${x.nodes[0].target.join(" ")}`));
    check(`axe: no WCAG 2.2 AA or best-practice violations, ${t}, ${w}px`, v.length === 0, v.join("; "));
    await ctx.close();
  }
}

// 2. Contrast of the colour tokens, resolved through the browser (text 4.5, controls and status colours 3)
{
  const { ctx, page } = await open(srv.link);
  for (const t of ["dark", "light"]) {
    await setTheme(page, t);
    const bad = await page.evaluate(() => {
      const probe = document.createElement("div"); document.body.appendChild(probe);
      const rgb = (v) => { probe.style.color = ""; probe.style.color = v; return getComputedStyle(probe).color.match(/[\d.]+/g).map(Number); };
      const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
      const lum = ([r, g, b]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
      const cr = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
      const tok = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
      const bgs = ["--bg-base", "--bg-surface", "--bg-elevated", "--bg-hover"];
      const out = [];
      for (const [list, min] of [[["--border-field", "--cyan", "--emerald", "--amber", "--rose", "--violet"], 3],
        [["--text-primary", "--text-secondary", "--text-muted", "--cyan-text", "--emerald-text", "--amber-text", "--rose-text", "--violet-text", "--pre-text"], 4.5]]) {
        for (const f of list) {
          if (!tok(f)) { out.push(`${f} missing`); continue; }
          for (const b of bgs) { const r = cr(rgb(tok(f)), rgb(tok(b))); if (r < min) out.push(`${f} on ${b} ${r.toFixed(2)}`); }
        }
      }
      probe.remove(); return out;
    });
    check(`token contrast: text >= 4.5, controls and status colours >= 3, ${t}`, bad.length === 0, bad.join("; "));
  }
  await ctx.close();
}

// 3. No sideways scroll on phones
for (const w of [390, 360]) {
  const { ctx, page } = await open(srv.link, { width: w, height: 800 });
  const sw = await page.evaluate(() => document.documentElement.scrollWidth);
  check(`no horizontal scroll at ${w}px`, sw <= w, `scrollWidth ${sw}`);
  await ctx.close();
}

// 4. The summary cards and the rows work from the keyboard
{
  const { ctx, page } = await open(srv.link);
  await page.locator('[data-act="decision:deny"]').focus();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(200);
  const r = await page.evaluate(() => ({
    filter: document.getElementById("filter-decision").value,
    rows: document.querySelectorAll("#audit-table-body tr.event-row").length,
    open: document.querySelectorAll("#audit-table-body tr.detail-row").length,
    inventoryHidden: document.getElementById("section-nhi").classList.contains("hidden"),
  }));
  check("Enter on the Denied card filters the audit table to the 3 denied calls and opens no row",
    r.filter === "deny" && r.rows === 3 && r.open === 0 && r.inventoryHidden, JSON.stringify(r));

  // 5. The focus ring of a row is visible and not clipped by the scrolling table
  const clipped = await page.evaluate(() => {
    const el = document.querySelector("#audit-table-body .row-toggle");
    if (!el) return ["row toggle missing"];
    el.focus();
    const cs = getComputedStyle(el), ext = parseFloat(cs.outlineOffset) + parseFloat(cs.outlineWidth);
    const b = el.getBoundingClientRect(), c = el.closest(".table-wrap").getBoundingClientRect();
    if (cs.outlineStyle === "none" || parseFloat(cs.outlineWidth) < 2) return ["no focus ring"];
    return b.left - ext < c.left - 0.5 || b.right + ext > c.right + 0.5 ? ["ring clipped by the table"] : [];
  });
  check("focus ring on an event row is fully visible", clipped.length === 0, clipped.join("; "));

  // 6. Toggle buttons say their state
  await page.click('.tab-btn[data-view="nhi"]');
  await page.waitForFunction(() => document.querySelectorAll("#nhi-list-container .nhi-item").length > 0, null, { timeout: 8000 }).catch(() => {});
  const a = await page.getAttribute("#nhi-btn-loose", "aria-pressed");
  await page.click("#nhi-btn-loose"); await page.waitForTimeout(150);
  const b = await page.getAttribute("#nhi-btn-loose", "aria-pressed");
  const loose = await page.evaluate(() => [...document.querySelectorAll("#nhi-list-container .nhi-name")].map((n) => n.textContent));
  const tab = await page.getAttribute('.tab-btn[data-view="nhi"]', "aria-pressed");
  check("the Loose Mode filter and the view tabs flip aria-pressed, and the filter shows only the loose folder",
    a === "false" && b === "true" && loose.join() === "~/.aws" && tab === "true", `before=${a} after=${b} loose=${loose} tab=${tab}`);
  await ctx.close();
}

// 7. Target sizes: >= 24px everywhere, >= 44px on touch phones
for (const [touch, min, w] of [[false, 24, 1440], [true, 44, 390]]) {
  const { ctx, page } = await open(srv.link, { width: w, height: 844, touch });
  const small = await page.evaluate((min) => [...document.querySelectorAll("button, select, input, a[href], [role=button], [tabindex]")]
    .filter((e) => e.offsetParent && e.getAttribute("tabindex") !== "-1")
    .map((e) => { const r = e.getBoundingClientRect(); return { c: (e.id || e.className || e.tagName).toString().split(" ")[0], h: Math.round(r.height), w: Math.round(r.width) }; })
    .filter((x) => x.h < min || x.w < min)
    .map((x) => `${x.c} ${x.w}x${x.h}`), min);
  const uniq = [...new Set(small)];
  check(`interactive targets >= ${min}px ${touch ? "on touch" : "with a mouse"}`, uniq.length === 0, uniq.slice(0, 6).join(", "));
  await ctx.close();
}

// 8. Dark is the default whatever the OS says, and the viewer's choice survives a reload
{
  const { ctx, page } = await open(srv.link, { colorScheme: "light" });
  const first = await theme(page);
  await page.click("#theme-toggle");
  await page.waitForTimeout(200);
  const chosen = await theme(page);
  await page.reload(); await page.waitForTimeout(1200);
  const again = await theme(page);
  check("theme starts dark even on a light OS, and the chosen light theme survives a reload",
    first === "dark" && chosen === "light" && again === "light", `first=${first} chosen=${chosen} reload=${again}`);

  // 9. Smallest rendered text is 12px or larger
  await page.locator(".row-toggle").first().click();
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
await stop(srv);

// 10. A live poll keeps keyboard focus and open rows
{
  const data = folder("poll");
  for (const i of [1, 2, 3, 4, 5]) appendLine(data, line(i));
  mark(data, "s1");
  const s = await startServer(data, { env: { HOME } });
  const { ctx, page } = await open(s.link);
  await page.locator("[data-clear]").focus();
  await page.waitForTimeout(2600);
  check("focus on a Clear mark button survives a live poll", await page.evaluate(() => document.activeElement.hasAttribute("data-clear")));

  await page.locator("#audit-table-body .row-toggle").nth(1).focus();
  await page.keyboard.press("Enter");
  const focusBefore = await page.evaluate(() => document.activeElement.getAttribute("data-focus"));
  appendLine(data, line(6, { decision: "allow", rule: "default-allow" }));
  await page.waitForTimeout(2600);
  const after = await page.evaluate(() => ({
    rows: document.querySelectorAll("#audit-table-body tr.event-row").length,
    open: document.querySelectorAll('#audit-table-body .row-toggle[aria-expanded="true"]').length,
    detail: (document.querySelector("#audit-table-body tr.detail-row") || {}).textContent || "",
    focus: document.activeElement.getAttribute("data-focus") || "",
  }));
  check("an open row stays open, on the same event, when a new event arrives",
    after.rows === 6 && after.open === 1 && after.detail.includes('"t4"'), JSON.stringify({ ...after, detail: after.detail.slice(0, 60) }));
  check("focus on a row survives the redraw that a new event causes", !!focusBefore && after.focus === focusBefore, `${focusBefore} -> ${after.focus}`);
  await ctx.close(); await stop(s);
}

// 11. An injection warning is counted, tinted and named on its row
{
  const data = folder("flag");
  appendLine(data, line(1));
  appendLine(data, line(9, { event: "result", decision: "allow", tool_name: "WebFetch", rule: null, input: { url: "https://example.com" },
    warnings: [{ marker: "ignore-previous", excerpt: "ignore previous instructions" }] }));
  mark(data, "s1", { id: "t9", tool: "WebFetch", markers: ["ignore-previous"], ts: "2026-11-07T20:00:09Z", agent: "claude-code",
    input: { url: "https://example.com/page" }, excerpts: ["ignore previous instructions"] });
  const s = await startServer(data, { env: { HOME } });
  const { ctx, page } = await open(s.link);
  for (const t of ["dark", "light"]) { // the marked-session card, with its link, in both themes
    await setTheme(page, t);
    await page.addScriptTag({ content: AXE });
    const v = await page.evaluate(async () => (await axe.run(document.getElementById("taint-banner"), { runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] }))
      .violations.map((x) => `${x.id} (${x.nodes.length}) e.g. ${x.nodes[0].target.join(" ")}`));
    const link = await page.evaluate(() => document.querySelectorAll('#taint-actions a[href="https://example.com/page"]').length);
    check(`axe: the marked-session card with its address link has no violations, ${t}`, v.length === 0 && link === 1, `${v.join("; ")} links=${link}`);
  }
  const r = await page.evaluate(() => {
    const row = document.querySelector("#audit-table-body tr.event-row");
    return { kpi: document.getElementById("kpi-flag-count").textContent, tinted: row.classList.contains("flagged-row"), text: row.textContent };
  });
  check("a reply with an injection warning: Flags card counts 1, the row is tinted and names the marker; an old line with no warned field says neither 'note sent to Claude' nor 'session marked'",
    r.kpi === "1" && r.tinted && r.text.includes("ignore-previous") && !/note sent to Claude|session marked/.test(r.text), JSON.stringify(r).slice(0, 200));
  await ctx.close(); await stop(s);
}

// 12. Log and session strings are text, never markup or script
{
  const data = folder("hostile");
  const hostile = "<img src=x onerror=alert(1)>";
  appendLine(data, line(1));
  appendLine(data, line(7, { tool_name: hostile, rule: hostile, step: hostile, tool_use_id: "q'\"><svg onload=alert(3)>", agent: hostile, session_id: hostile, reason: hostile, input: { command: hostile } }));
  mark(data, "a');alert(2);('", { id: "q'\"><svg onload=alert(4)>", tool: hostile, markers: [hostile], ts: hostile, agent: hostile, input: { url: hostile }, excerpts: [hostile] });
  mark(data, hostile, { id: 7, tool: 7, markers: "x", input: "y", excerpts: 9 });
  mark(data, "js", { id: "j1", tool: "WebFetch", markers: ["ignore-previous"], input: { url: "javascript:alert(5)" } });
  mark(data, "red", { id: "r1", tool: "WebFetch", markers: ["ignore-previous"], input: { url: "https://example.com/?t=[REDACTED:github-token]" } });
  const s = await startServer(data, { env: { HOME } });
  const { ctx, page } = await open(s.link);
  const buttons = await page.locator("[data-clear]").count();
  await page.locator(".row-toggle").first().click();
  await page.locator("[data-clear]").first().click();
  await page.waitForTimeout(600);
  const r = await page.evaluate((h) => ({ injected: document.querySelectorAll("#audit-table-body img, #audit-table-body svg, #taint-actions img, #taint-actions svg, #filter-agent img").length,
    links: document.querySelectorAll("#taint-actions a").length,
    shown: document.getElementById("audit-table-body").textContent.includes(h) && document.getElementById("taint-actions").textContent.includes(h) }), hostile);
  check("hostile log and session text is shown as text: no element is made, no dialog opens, no script error; a javascript: or redacted address is never a link",
    buttons === 4 && r.links === 0 && r.injected === 0 && r.shown && page.dialogs.length === 0 && page.errors.length === 0, `${buttons} ${JSON.stringify(r)} dialogs=${page.dialogs} errors=${page.errors}`);
  await ctx.close(); await stop(s);
}

// 13. With no server the page says so and shows nothing made up
{
  const { ctx, page } = await open("file://" + path.join(REPO, "index.html"));
  const html = fs.readFileSync(path.join(REPO, "index.html"), "utf8");
  const r = { mode: await mode(page), detail: await detail(page), rows: await rowCount(page), cards: await page.locator(".agent-card").count(), nhis: await page.locator(".nhi-item").count() };
  check("opened as a file: Not Connected, how to start the server, no rows, no inventory, and no sample data in the file",
    r.mode === "Not Connected" && r.detail.includes("make dashboard") && r.rows === 0 && r.cards === 0 && r.nhis === 0 && !/sample/i.test(html) && page.errors.length === 0, JSON.stringify(r));
  await ctx.close();
}

await browser.close();
console.log(failures() ? `\n${failures()} checks FAILED` : "\nall checks passed");
process.exit(failures() ? 1 : 0);
