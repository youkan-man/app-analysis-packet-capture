/* Chromium coverage and genuine screenshots for Info selections, menus and filters. */
const { chromium } = require("playwright");
const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert/strict");

(async () => {
  fs.mkdirSync("artifacts", { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));

  async function rowsEqual(numbers) {
    await page.waitForFunction(expected => {
      const rows = Array.from(document.querySelectorAll("#packet-rows tr"));
      return rows.length === expected.length && rows.every((row, index) =>
        Number(row.cells[0]?.textContent) === expected[index]);
    }, numbers, { timeout: 15000 });
  }
  async function clearAll() {
    if (await page.locator("#info-clear").isEnabled()) await page.locator("#info-clear").click();
    await page.locator("#clear-filter").click();
    await rowsEqual([1, 2]);
  }

  try {
    await page.goto("http://127.0.0.1:18080/", { waitUntil: "networkidle" });
    await page.locator("#file-input").setInputFiles(path.resolve("artifacts/test.pcap"));
    await rowsEqual([1, 2]);
    await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });
    const firstInfo = await page.locator("#packet-rows tr").first().locator(".info-text").textContent();
    assert.match(firstInfo, /query/i);
    await page.screenshot({ path: "artifacts/packets-desktop.png", fullPage: true });

    // Mouse text selection inside the Info cell must offer immediate actions.
    await page.evaluate(() => {
      const text = document.querySelector("#packet-rows tr .info-text").firstChild;
      const source = text.textContent;
      const start = source.toLowerCase().indexOf("query");
      if (start < 0) throw new Error("DNS query text absent");
      const range = document.createRange();
      range.setStart(text, start);
      range.setEnd(text, start + 5);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      const r = range.getBoundingClientRect();
      text.parentElement.dispatchEvent(new MouseEvent("mouseup", {
        bubbles: true, button: 0, clientX: r.left + 1, clientY: r.top + 2,
      }));
    });
    await page.locator("#selection-tools").waitFor({ state: "visible" });
    assert.equal(await page.locator("#selection-text").textContent(), firstInfo.match(/query/i)[0]);
    await page.screenshot({ path: "artifacts/info-selection-desktop.png", fullPage: true });
    await page.locator("#selection-tools [data-info-action=replace]").click();
    await rowsEqual([1]);
    assert.match(await page.locator("#info-chips").textContent(), /query/i);
    await page.screenshot({ path: "artifacts/info-filtered-desktop.png", fullPage: true });
    await clearAll();

    // Right click the Info cell without selection: use full Info field.
    await page.evaluate(() => window.getSelection().removeAllRanges());
    await page.locator("#packet-rows tr").first().locator("td.info-cell").click({ button: "right" });
    await page.locator("#packet-context-menu").waitFor({ state: "visible" });
    assert.match(await page.locator(".context-heading").first().textContent(), /Info/);
    await page.screenshot({ path: "artifacts/info-context-menu.png", fullPage: true });
    await page.getByRole("menuitem", { name: "含まない 〔この条件に置換〕" }).click();
    await rowsEqual([2]);

    // Mix OR with negative clause, remove one clause, then AND a second condition.
    await page.locator("#info-query").fill("query");
    await page.locator("#info-mode").selectOption("contains");
    await page.locator("#info-join").selectOption("or");
    await page.locator("#info-form button[type=submit]").click();
    await rowsEqual([1, 2]);
    assert.match(await page.locator("#info-chips").textContent(), /OR/);
    await page.locator(".info-chip-remove").first().click();
    await rowsEqual([1]);
    await page.locator("#info-join").selectOption("and");
    await page.locator("#info-query").fill("example.com");
    await page.locator("#info-form button[type=submit]").click();
    await rowsEqual([1]);
    assert.match(await page.locator("#info-chips").textContent(), /AND/);
    await clearAll();

    // Existing display-filter engine still handles source addresses and ports.
    await page.locator("#packet-rows tr").nth(1).locator("td").nth(2).click({ button: "right" });
    await page.locator("#packet-context-menu").waitFor({ state: "visible" });
    assert.match(await page.locator("#packet-context-menu").textContent(), /ip.src/);
    await page.screenshot({ path: "artifacts/source-context-menu.png", fullPage: true });
    await page.getByRole("menuitem", { name: "この値で表示" }).click();
    await rowsEqual([2]);
    assert.match(await page.locator("#display-filter").inputValue(), /ip.src == 203.0.113.2/);
    await clearAll();

    // Context-key / Shift+F10, plus keyboard dismissal and row action discovery.
    const firstRow = page.locator("#packet-rows tr").first();
    await firstRow.focus();
    await firstRow.press("Shift+F10");
    await page.locator("#packet-context-menu").waitFor({ state: "visible" });
    await page.keyboard.press("Escape");
    await page.locator("#packet-context-menu").waitFor({ state: "hidden" });
    await firstRow.locator(".packet-row-actions").click();
    await page.locator("#packet-context-menu").waitFor({ state: "visible" });
    await page.keyboard.press("Escape");

    // Case-sensitive Info matching is distinct from Wireshark display filters.
    await page.locator("#info-case").check();
    await page.locator("#info-join").selectOption("replace");
    await page.locator("#info-query").fill("standard query");
    await page.locator("#info-form button[type=submit]").click();
    await rowsEqual([]);
    await page.locator("#info-case").uncheck();
    await page.locator("#info-form button[type=submit]").click();
    await rowsEqual([1]);
    await clearAll();

    // Saved named filters capture both the native expression and Info clauses.
    await page.locator("#display-filter").fill("dns");
    await page.locator("#filter-form button[type=submit]").click();
    await rowsEqual([1]);
    await page.locator("#info-query").fill("query");
    await page.locator("#info-join").selectOption("replace");
    await page.locator("#info-form button[type=submit]").click();
    await rowsEqual([1]);
    page.once("dialog", dialog => dialog.accept("DNS + Info"));
    await page.locator("#save-filter").click();
    await clearAll();
    await page.locator("#saved-filters").selectOption({ label: "DNS + Info" });
    await rowsEqual([1]);
    assert.equal(await page.locator("#display-filter").inputValue(), "dns");
    assert.match(await page.locator("#info-chips").textContent(), /query/);

    // Existing nested Wireshark field builder continues to work with Info predicates.
    await page.locator("#toggle-builder").click();
    await page.locator("#condition-root .rule-value").fill("192.0.2.10");
    await page.locator("#apply-builder").click();
    await rowsEqual([1]);
    await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });
    await page.screenshot({ path: "artifacts/filter-builder-desktop.png", fullPage: true });

    // Mobile remains navigable with visible Info controls and context actions.
    await page.locator("#close-builder").click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator("#info-query").scrollIntoViewIfNeeded();
    await page.screenshot({ path: "artifacts/packets-mobile.png", fullPage: true });
    await firstRow.locator(".packet-row-actions").click();
    await page.locator("#packet-context-menu").waitFor({ state: "visible" });
    await page.screenshot({ path: "artifacts/info-context-mobile.png", fullPage: true });
    assert.deepEqual(errors, []);
    console.log("Browser smoke passed: substring selection, menus, Info AND/OR, raw display, presets, desktop/mobile");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
