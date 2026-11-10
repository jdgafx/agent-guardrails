// Regressions for index.html: the reader's place under live events, and focus after clearing a session mark.
// Real server, real log file, real mark file. Nothing is mocked.
// Usage: node tests/dashboard-regress.mjs index.html   (run from the repo root; needs playwright and python3)
import fs from "fs";
import path from "path";
import { appendLine, browser, check, failures, folder, home, line, mark, open, startServer, stop } from "./dashboard-server.mjs";

const data = folder("regress");
for (let i = 1; i <= 40; i++) appendLine(data, line(i, { input: { file_path: "/x" + i + "." } }));
mark(data, "s1");
const srv = await startServer(data, { env: { HOME: home() } });
const { ctx, page } = await open(srv.link, { height: 700 });

{ // A: the row someone is reading does not slide when new events arrive above it
  const find = () => page.evaluate(() => {
    const row = [...document.querySelectorAll("#audit-table-body tr.event-row")].find((r) => r.textContent.includes("/x20."));
    return row ? Math.round(row.getBoundingClientRect().top) : null;
  });
  await page.evaluate(() => {
    const row = [...document.querySelectorAll("#audit-table-body tr.event-row")].find((r) => r.textContent.includes("/x20."));
    window.scrollBy(0, row.getBoundingClientRect().top - 120);
  });
  await page.waitForTimeout(300);
  const before = await find();
  for (const i of [41, 42, 43]) appendLine(data, line(i, { input: { file_path: "/x" + i + "." } }));
  await page.waitForFunction(() => document.querySelectorAll("#audit-table-body tr.event-row").length === 43, null, { timeout: 6000 }).catch(() => {});
  const after = await find();
  const rows = await page.locator("#audit-table-body tr.event-row").count();
  check("a row being read stays in place while new events arrive", rows === 43 && before !== null && after !== null && Math.abs(after - before) <= 1, `rows ${rows}, before ${before}, after ${after}`);
}
{ // B: the Clear mark button goes away when it is used; focus must land somewhere, and the result is announced
  await page.locator("[data-clear]").focus();
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => /cleared/i.test(document.getElementById("live-status").textContent), null, { timeout: 4000 }).catch(() => {});
  const r = await page.evaluate(() => ({ tag: document.activeElement.tagName, id: document.activeElement.id, live: document.getElementById("live-status").textContent,
    buttons: document.querySelectorAll("[data-clear]").length, banner: document.getElementById("taint-banner").classList.contains("hidden") }));
  check("after clearing a mark, focus is not lost, the banner is gone and the mark file is deleted",
    r.tag !== "BODY" && r.buttons === 0 && r.banner && !fs.existsSync(path.join(data, "state", "s1.taint")), JSON.stringify(r));
  check("clearing a mark is announced", /cleared/i.test(r.live), r.live);
}
await ctx.close(); await stop(srv);
await browser.close();
process.exit(failures() ? 1 : 0);
