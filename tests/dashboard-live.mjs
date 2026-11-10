// The dashboard page against the real server and the real hooks, in Chromium. Nothing is mocked.
// Usage: node tests/dashboard-live.mjs   (run from the repo root; needs playwright, chromium and python3)
// Not part of CI (CI has no Node step). tests/e2e/test_t031_dashboard.py runs it when Node is there.
import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { INJECTION, REPO, TMP, browser, check, dayFile, detail, failures, folder, home, lines, mode, open, post, pre, rowCount, rows, startServer, stop, waitRows } from "./dashboard-server.mjs";

const firewall = /firewall/i;
const text = (page, sel) => page.evaluate((s) => document.querySelector(s).innerText.replace(/\s+/g, " ").trim(), sel);
const banner = (page, id) => page.evaluate((i) => { const b = document.getElementById(i); return b.classList.contains("hidden") ? "" : b.innerText.replace(/\s+/g, " ").trim(); }, id);
const openRow = async (page, index) => {
  await page.locator("#audit-table-body .row-toggle").nth(index).click();
  return page.locator("#audit-table-body tr.detail-row").first().innerText();
};

// ===== a real hook step shows up within seconds; the key guards the page
{
  const data = folder("c2");
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  check("2  page is live on the server", (await mode(page)) === "Live 127.0.0.1", await mode(page));
  pre(data, "Read", { file_path: ".env" }, "t2");
  const ok = await page.waitForFunction(() => [...document.querySelectorAll("#audit-table-body tr.event-row")].some((tr) => tr.textContent.includes("deny-env-files") && tr.children[3].textContent.trim() === "deny"), null, { timeout: 4000 }).then(() => true, () => false);
  check("2  a real Read of .env shows a deny row with rule deny-env-files within 4 s", ok);
  await ctx.close();
  const noKey = await open(srv.base + "/");
  check("55 page without the key gets 403 and shows no data", noKey.resp.status() === 403 && (await noKey.page.textContent("body")).includes("Forbidden") === true, String(noKey.resp.status()));
  await noKey.ctx.close();
  const wrong = await open(srv.base + "/?key=wrong");
  check("56 page with a wrong key gets 403", wrong.resp.status() === 403, String(wrong.resp.status()));
  await wrong.ctx.close();
  await stop(srv);
}

// ===== the states of the header, from real folders
{
  const empty = folder("c27");
  const srv = await startServer(empty);
  const { ctx, page } = await open(srv.link);
  const d = await detail(page), table = await text(page, "#audit-table-body");
  check("27 empty folder: live, the header says 'No audit log yet in <folder>', the table says no call is logged yet",
    (await mode(page)) === "Live 127.0.0.1" && d === "No audit log yet in " + empty && table.includes("No tool call has been logged yet") && (await rowCount(page)) === 0, `${d} | ${table}`);
  const total = (await (await fetch(srv.base + "/api/policy?key=" + srv.key)).json()).rules.length;
  const shown = await page.textContent("#kpi-rule-count");
  const listed = await page.locator("#policy-table-body tr").count();
  check(`29 the rules card and the rules table show the ${total} rules in force`, total > 0 && shown === String(total) && listed === total, `${shown} ${listed}`);
  const words = [await page.title(), await text(page, ".topbar"), await text(page, ".kpi-grid"), await text(page, ".nav-tabs"), table];
  check("50 title, header, cards, tabs and empty table have no 'firewall'", !words.some((t) => firewall.test(t)), words.join(" | ").slice(0, 200));
  await ctx.close(); await stop(srv);
}
{
  const data = folder("c32");
  pre(data, "Read", { file_path: ".env" }, "t32");
  fs.writeFileSync(path.join(data, "policy.json"), JSON.stringify({ version: 1, rules: [{ id: "bad", decision: "ask", kind: "command", match: ["("], reason: "x" }] }));
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  const b = await banner(page, "policy-banner");
  check("32 a broken added policy shows the policy banner with the error, and the pill says Policy: Error",
    b.includes("bad regex") && b.includes("policy.json") && (await page.textContent("#policy-label")) === "Policy: Error", b);
  await ctx.close(); await stop(srv);
}
{
  const data = folder("c37");
  fs.writeFileSync(path.join(data, "policy.json"), JSON.stringify({ version: 1, isolation: true }));
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  const t = await page.textContent("#iso-label");
  check("37 isolation in the policy: the pill says Isolation: ON", t.includes("Isolation: ON"), t);
  await ctx.close(); await stop(srv);
}

// ===== the server stops, comes back
{
  const data = folder("c40");
  pre(data, "Read", { file_path: ".env" }, "t40");
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  const before = await rowCount(page);
  await stop(srv);
  await page.waitForFunction(() => document.getElementById("conn-label").textContent === "Server Offline", null, { timeout: 6000 }).catch(() => {});
  const d = await detail(page);
  check("40 server stopped: Server Offline, the header says it stopped answering, the rows stay",
    (await mode(page)) === "Server Offline" && d.includes("stopped answering") && before > 0 && (await rowCount(page)) === before, `${await mode(page)} | ${d}`);
  const srv2 = await startServer(data, { port: srv.port });
  await page.waitForTimeout(4500);
  check("41 a restarted server has a new key: the old page stays offline and keeps its rows",
    (await mode(page)) === "Server Offline" && (await rowCount(page)) === before, await mode(page));
  await page.goto(srv2.link);
  await page.waitForTimeout(1800);
  check("41 the new printed link is live again with the same rows", (await mode(page)) === "Live 127.0.0.1" && (await rowCount(page)) === before, `${await mode(page)} ${await rowCount(page)}`);
  await ctx.close(); await stop(srv2);
}
{
  // The same key, a server that stops answering and then answers again: the page recovers by itself and keeps every row.
  const data = folder("c41");
  pre(data, "Read", { file_path: ".env" }, "t41");
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  srv.proc.kill("SIGSTOP");
  const off = await page.waitForFunction(() => document.getElementById("conn-label").textContent === "Server Offline", null, { timeout: 8000 }).then(() => true, () => false);
  srv.proc.kill("SIGCONT");
  const live = await page.waitForFunction(() => document.getElementById("conn-label").textContent === "Live 127.0.0.1", null, { timeout: 8000 }).then(() => true, () => false);
  check("41 a frozen server turns the page offline, and it is live again with its 1 row once the server answers", off && live && (await rowCount(page)) === 1, `${off} ${live} ${await rowCount(page)}`);
  await ctx.close(); await stop(srv);
}

// ===== the rows, from the real hooks
{
  const data = folder("rows");
  pre(data, "Read", { file_path: ".env" }, "d1");
  pre(data, "WebFetch", { url: "https://example.com" }, "f1");
  post(data, "WebFetch", { url: "https://example.com" }, "f1", INJECTION);
  pre(data, "Bash", { command: "ls" }, "a1", "s2"); // its own session: the flagged page marks s1, not s2
  post(data, "Bash", { command: "ls" }, "a1", "x", "s2");
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  const all = await rows(page);
  const fl = all.find((r) => r.tool === "WebFetch"), al = all.find((r) => r.tool === "Bash"), de = all.find((r) => r.tool === "Read");
  check("42 flagged row: tinted, 'note sent to Claude', 'session marked' (the real hook wrote warned and tainted), both markers, name starts with the time and the decision",
    fl && /flagged-row/.test(fl.cls) && ["note sent to Claude", "session marked", "ignore-previous", "exfil-request"].every((t) => fl.text.includes(t)) && /^\d{4}-.*Z, allow, claude-code, WebFetch/.test(fl.label), JSON.stringify(fl));
  const drawer = await openRow(page, all.indexOf(fl));
  check("42 flagged row opened: the full record with warned, tainted and both markers", ['"warned": true', '"tainted": true', "ignore-previous", "exfil-request", '"session_id": "s1"'].every((t) => drawer.includes(t)), drawer.slice(0, 300));
  await page.locator("#audit-table-body .row-toggle").nth(all.indexOf(fl)).click();
  check("43 unflagged allow: decision allow, rule default-allow, no signal badge, not tinted",
    al && al.decision === "allow" && al.rule === "default-allow" && !/flagged-row/.test(al.cls) && !/note sent|session marked|tainted/.test(al.text), JSON.stringify(al));
  check("44 denied call: decision deny, rule deny-env-files", de && de.decision === "deny" && de.rule === "deny-env-files", JSON.stringify(de));
  const cards = await page.evaluate(() => ["kpi-deny-count", "kpi-ask-count", "kpi-flag-count"].map((id) => document.getElementById(id).textContent).join(","));
  const pill = await page.textContent("#taint-label");
  const why = await banner(page, "taint-banner");
  check("45 cards: 1 denied, 0 asked, 1 flagged; the banner names the marked session, the call, the address it fetched, when, and the phrases",
    cards === "1,0,1" && pill === "Session Marked (1)" && (await page.locator("[data-clear]").count()) === 1
    && ["Session s1", "WebFetch by claude-code", "https://example.com", "ignore-previous", "exfil-request"].every((t) => why.toLowerCase().includes(t.toLowerCase()))
    && /marked 20\d\d-\d\d-\d\dT/.test(why), `${cards} ${pill} ${why}`);
  const link = await page.evaluate(() => { const a = document.querySelector("#taint-actions a"); return a ? [a.getAttribute("href"), a.target, a.rel, Math.round(a.getBoundingClientRect().height) >= 24].join(" ") : ""; });
  check("45 the fetched address is a link that opens in a new tab without handing this page to it", link === "https://example.com _blank noopener noreferrer true", link);
  await page.click("[data-session]");
  const mine = await rows(page);
  check("45 'Show its events' switches to the audit trail and shows only that session's rows",
    (await page.inputValue("#filter-search")) === "s1" && mine.length === 2 && mine.every((r) => r.tool !== "Bash") && (await page.evaluate(() => document.getElementById("section-nhi").classList.contains("hidden"))), JSON.stringify(mine.map((r) => r.tool)));
  await page.click('.tab-btn[data-view="overview"]');
  await page.click("#reset-filters");
  await page.selectOption("#filter-decision", "deny");
  const onlyDeny = await rows(page);
  await page.click("#reset-filters");
  await page.selectOption("#filter-signal", "flagged");
  const onlyFlag = await rows(page);
  await page.click("#reset-filters");
  await page.selectOption("#filter-agent", "claude-code");
  const byAgent = await rowCount(page);
  await page.click("#reset-filters");
  await page.fill("#filter-search", "example.com");
  const bySearch = await rows(page);
  await page.click("#reset-filters");
  check("46 filters: Deny shows only the Read row, Flagged only the WebFetch row, the agent filter all 3, the search box only the WebFetch row, Reset brings back 3",
    onlyDeny.length === 1 && onlyDeny[0].tool === "Read" && onlyFlag.length === 1 && onlyFlag[0].tool === "WebFetch" && byAgent === 3 && bySearch.length === 1 && bySearch[0].tool === "WebFetch" && (await rowCount(page)) === 3,
    `${onlyDeny.map((r) => r.tool)} ${onlyFlag.map((r) => r.tool)} ${byAgent} ${bySearch.map((r) => r.tool)}`);

  // 47: a copied flagged result line that is warned but not marked, and an old line with no warned field
  const flagged = lines(data).find((l) => l.event === "result" && l.warnings.length);
  const copy = { ...flagged, tool_use_id: "f2", warned: true, tainted: false };
  const old = { ...flagged, tool_use_id: "f3" };
  delete old.warned; delete old.tainted;
  fs.appendFileSync(dayFile(data), JSON.stringify(copy) + "\n" + JSON.stringify(old) + "\n");
  await waitRows(page, 5);
  const listed = await rows(page);
  check("47 warned true, tainted false: 'note sent to Claude' and no 'session marked'; an old line with no warned field: the markers only",
    listed.length === 5 && listed[1].text.includes("note sent to Claude") && !listed[1].text.includes("session marked")
    && listed[0].text.includes("ignore-previous") && !/note sent to Claude|session marked/.test(listed[0].text), JSON.stringify(listed.slice(0, 2)));
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: path.join(TMP, "rows-1440.png") });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.screenshot({ path: path.join(TMP, "rows-390.png") });
  await ctx.close(); await stop(srv);
}

// ===== an ask that ran, and a result with no Pre record
{
  const data = folder("ask");
  pre(data, "Bash", { command: "git push origin main" }, "p1");
  post(data, "Bash", { command: "git push origin main" }, "p1", "x");
  post(data, "Bash", { command: "echo hi" }, "u1", "hi"); // a real Post with no Pre memo: decision "unknown"
  const srv = await startServer(data);
  const { ctx, page } = await open(srv.link);
  const all = await rows(page);
  const pushes = all.filter((r) => r.rule === "ask-git-push");
  check("48 ask then ran: a decision row and a result row, both ask, both ask-git-push; the Ask card counts 2",
    pushes.length === 2 && pushes.every((r) => r.decision === "ask") && pushes.map((r) => r.event).sort().join() === "decision,result" && (await page.textContent("#kpi-ask-count")) === "2", JSON.stringify(all));
  const unknown = all.find((r) => r.text.includes("echo hi"));
  check("49 a result with no Pre record shows decision unknown, and is not counted as allowed, asked or denied",
    unknown && unknown.decision === "unknown" && (await page.textContent("#kpi-deny-count")) === "0", JSON.stringify(unknown));
  await ctx.close(); await stop(srv);
}

// ===== hostile log text, through the real server
{
  const data = folder("c52");
  pre(data, "Read", { file_path: ".env" }, "h0");
  const hostile = "<img src=x onerror=alert(1)>";
  const copy = { ...lines(data)[0], tool_use_id: "h1", input: { file_path: hostile } };
  fs.appendFileSync(dayFile(data), JSON.stringify(copy) + "\n");
  const srv = await startServer(data);
  const api = await (await fetch(srv.base + "/api/events?after=&key=" + srv.key)).json();
  const same = api.length === 2 && JSON.stringify(Object.fromEntries(Object.entries(api[1]).filter(([k]) => k !== "cursor"))) === JSON.stringify(copy);
  const { ctx, page } = await open(srv.link);
  await openRow(page, 0);
  const imgs = await page.evaluate(() => document.querySelectorAll("#audit-table-body img").length);
  const shown = await page.evaluate((t) => document.getElementById("audit-table-body").textContent.includes(t), hostile);
  await page.waitForTimeout(500);
  check("52 hostile log text: the API returns the same values plus cursor; the page shows it as text, no img, no dialog", same && imgs === 0 && shown && page.dialogs.length === 0, `${same} ${imgs} ${shown} ${page.dialogs}`);
  await ctx.close(); await stop(srv);
}

// ===== the inventory, and the one-click clear of a marked session
{
  const data = folder("c61");
  const h = home();
  pre(data, "WebFetch", { url: "https://example.com" }, "f1", "risky");
  post(data, "WebFetch", { url: "https://example.com" }, "f1", INJECTION, "risky");
  const markFile = path.join(data, "state", "risky.taint");
  const srv = await startServer(data, { env: { HOME: h, EXAMPLE_API_KEY: "value-never-shown" } });
  const { ctx, page } = await open(srv.link);
  await page.waitForFunction(() => document.querySelectorAll(".agent-card").length > 0, null, { timeout: 8000 }).catch(() => {});
  const inv = await page.evaluate(() => document.getElementById("section-nhi").innerText);
  const whole = await page.content();
  check("61 the inventory shows this computer's agents, a risk level and secret names, never a value",
    /Codex/.test(inv) && /NOT GUARDED/.test(inv) && /(CRITICAL|HIGH)/.test(inv) && inv.includes("EXAMPLE_API_KEY") && inv.includes("~/.ssh") && /Scanned 20\d\d-/i.test(inv) && !whole.includes("value-never-shown"), inv.slice(0, 300));
  const btn = page.locator("[data-clear]");
  const shown = (await btn.count()) === 1 && (await btn.getAttribute("aria-label")).includes("risky") && (await banner(page, "taint-banner")).includes("https://example.com");
  await btn.click();
  const said = await page.waitForFunction(() => /cleared/i.test(document.getElementById("live-status").textContent), null, { timeout: 3000 }).then(() => true, () => false);
  const gone = !fs.existsSync(markFile) && (await btn.count()) === 0 && (await banner(page, "taint-banner")) === "";
  pre(data, "Bash", { command: "ls" }, "after-clear", "risky");
  const asked = lines(data).some((l) => l.tool_use_id === "after-clear" && l.event === "decision");
  const logged = lines(data).filter((l) => l.event === "mark-cleared" && l.session_id === "risky" && l.agent === "dashboard").length;
  await page.waitForTimeout(2600);
  const stays = (await btn.count()) === 0 && (await mode(page)) === "Live 127.0.0.1" && (await rows(page)).some((r) => r.agent === "dashboard" && r.event === "mark-cleared");
  check("62 one click clears the mark: the banner goes, the file is gone, the next call is not asked, and the log and the page say who did it",
    shown && gone && !asked && logged === 1 && said && stays && page.dialogs.length === 0, `${shown} ${gone} ${asked} ${logged} ${said} ${stays}`);
  await ctx.close(); await stop(srv);
}

// ===== the other two page test files pass too
for (const script of ["tests/dashboard-check.mjs", "tests/dashboard-regress.mjs"]) {
  const r = spawnSync("node", [script, "index.html"], { cwd: REPO, encoding: "utf8" });
  check(`53 node ${script} index.html exits 0`, r.status === 0, (r.stdout || "").split("\n").filter((l) => l.startsWith("FAIL")).join(" | ") + (r.stderr || "").slice(0, 300));
}

await browser.close();
console.log(failures() ? `\n${failures()} checks FAILED (screenshots in ${TMP})` : `\nall checks passed (screenshots in ${TMP})`);
process.exit(failures() ? 1 : 0);
