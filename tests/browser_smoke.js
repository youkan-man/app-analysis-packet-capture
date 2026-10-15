/* Real Chromium journeys for generic screen filters, neighbours, pins and comparison. */
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

  const realRows = () => page.locator("#packet-rows tr:not(.virtual-spacer)");
  async function waitNumbers(numbers) {
    await page.waitForFunction(expected => {
      const rows = Array.from(document.querySelectorAll("#packet-rows tr:not(.virtual-spacer)"));
      return rows.length === expected.length && rows.every((row, index) => Number(row.dataset.number) === expected[index]);
    }, numbers, { timeout: 20000 });
  }
  async function waitReady() {
    await page.waitForFunction(() => !document.querySelector("#status-dot")?.classList.contains("busy"), null, { timeout: 20000 });
    if (await realRows().count()) await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });
  }
  async function clearFilters() {
    if (!(await page.locator("#filter-drawer").isVisible())) await page.locator("#toggle-filter").click();
    await page.locator("#clear-filters").click();
    await waitNumbers([1,2,3,4,5,6,7]);
    await waitReady();
  }

  try {
    await page.goto("http://127.0.0.1:18080/", { waitUntil: "networkidle" });
    assert.equal(await page.locator("#prev-page, #next-page, #page-number").count(), 0);
    assert.equal(await page.locator("#info-query, .info-search").count(), 0);
    await page.locator("#file-input").setInputFiles(path.resolve("artifacts/test.pcap"));
    await waitNumbers([1,2,3,4,5,6,7]);
    await waitReady();
    const packetHeight = await page.locator(".packet-section").evaluate(node => node.getBoundingClientRect().height);
    const inspectHeight = await page.locator(".inspect-grid").evaluate(node => node.getBoundingClientRect().height);
    assert(packetHeight > inspectHeight, "packet data list should remain the primary surface");
    await page.screenshot({ path: "artifacts/data-view-desktop.png", fullPage: true });

    await realRows().first().locator('td[data-field="source"]').click({ button: "right" });
    await page.locator("#context-menu").waitFor({ state: "visible" });
    assert.match(await page.locator("#context-menu").textContent(), /Source/);
    await page.getByRole("menuitem", { name: "この値だけ表示" }).click();
    await waitNumbers([1,5]);
    assert.match(await page.locator("#active-filters").textContent(), /Source/);

    await realRows().first().locator('td[data-field="source"]').click({ button: "right" });
    await page.getByRole("menuitem", { name: "前後1件" }).click();
    await waitNumbers([1,2,4,5,6]);
    assert.equal(await page.locator("#packet-rows tr.context-row").count(), 3);
    await waitReady();
    await page.screenshot({ path: "artifacts/filter-neighbours-desktop.png", fullPage: true });
    await clearFilters();

    await page.locator("#close-filter").click();
    await page.evaluate(() => {
      const span = document.querySelector('#packet-rows tr[data-number="2"] td[data-field="source"] .value-text');
      const text = span.firstChild;
      const range = document.createRange();
      range.setStart(text, 0); range.setEnd(text, "203.0.113".length);
      window.getSelection().removeAllRanges(); window.getSelection().addRange(range);
      const rect = range.getBoundingClientRect();
      span.parentElement.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, button: 0, clientX: rect.left + 2, clientY: rect.top + 2 }));
    });
    await page.locator("#selection-tools").waitFor({ state: "visible" });
    await page.locator('#selection-tools [data-selection="replace"]').click();
    await waitNumbers([2,6]);
    await clearFilters();

    await page.locator("#add-condition").click();
    const rule = page.locator("#filter-groups .filter-rule").first();
    await rule.locator("select").first().selectOption("protocol");
    await rule.locator("select").nth(1).selectOption("equals");
    await rule.locator("input").fill("TCP");
    await page.locator("#apply-filters").click();
    await waitNumbers([2,4,6]);
    await waitReady();
    assert.equal(await page.locator(".advanced-filter[open]").count(), 0);
    await page.screenshot({ path: "artifacts/filter-drawer-desktop.png", fullPage: true });
    await clearFilters();
    await page.locator("#close-filter").click();

    await realRows().nth(1).locator(".pin-button").click();
    await realRows().nth(3).locator(".pin-button").click();
    assert.equal(await page.locator("#pin-chips .pin-chip").count(), 2);
    await page.locator("#compare-pins").click();
    await page.locator("#compare-panel").waitFor({ state: "visible" });
    await page.locator("#compare-table tbody tr").first().waitFor({ timeout: 20000 });
    assert.equal(await page.locator("#compare-table thead th").count(), 3);
    assert(await page.locator("#compare-table td.different").count() > 0);
    await page.screenshot({ path: "artifacts/compare-desktop.png", fullPage: true });
    await page.locator("#close-compare").click();

    const second = realRows().nth(1);
    await second.focus(); await second.press("Shift+F10");
    await page.locator("#context-menu").waitFor({ state: "visible" });
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 390, height: 844 });
    await second.locator('td[data-field="info"]').click({ button: "right" });
    await page.locator("#context-menu").waitFor({ state: "visible" });
    await page.screenshot({ path: "artifacts/context-mobile.png", fullPage: false });
    assert.deepEqual(errors, []);
    console.log("Browser smoke passed: continuous list, generic filters, neighbour context, pins and comparison");
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
