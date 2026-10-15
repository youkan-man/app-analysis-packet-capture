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

  async function selectText(locator, text) {
    await locator.scrollIntoViewIfNeeded();
    const box = await locator.evaluate((node, text) => {
      const textNode = node.firstChild;
      const start = textNode.textContent.indexOf(text);
      if (start < 0) throw new Error('Selection text is missing: ' + text);
      const range = document.createRange();
      range.setStart(textNode, start); range.setEnd(textNode, start + text.length);
      const r = range.getBoundingClientRect();
      return {left:r.left, right:r.right, y:r.top + r.height/2};
    }, text);
    const priorView = await page.evaluate(() => JSON.stringify(window.PacketApp.state.view));
    await page.mouse.move(box.left + .5, box.y); await page.mouse.down();
    await page.mouse.move(box.right - .5, box.y, {steps: 8}); await page.mouse.up();
    assert.equal(await page.evaluate(() => window.getSelection().toString()), text);
    assert.equal(await page.locator('#selection-tools, [data-selection]').count(), 0);
    assert.equal(await page.locator('#context-menu').isVisible(), false);
    assert.equal(await page.evaluate(() => JSON.stringify(window.PacketApp.state.view)), priorView);
    return {x:box.left + 2, y:box.y};
  }

  try {
    await page.goto("http://127.0.0.1:18080/", { waitUntil: "networkidle" });
    assert.equal(await page.locator("#prev-page, #next-page, #page-number").count(), 0);
    assert.equal(await page.locator("#info-query, .info-search").count(), 0);
    assert.equal(await page.locator("#selection-tools, [data-selection]").count(), 0);
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
    const selectedPoint = await selectText(
      page.locator('#packet-rows tr[data-number="2"] td[data-field="source"] .value-text'), '203.0.113');
    await page.screenshot({path: 'artifacts/text-selection-no-popup.png'});
    await page.mouse.click(selectedPoint.x, selectedPoint.y, {button: 'right'});
    await page.getByRole('menuitem', {name: '選択部分を含む', exact: true}).click();
    await waitNumbers([2,6]);
    await waitReady();
    const andPoint = await selectText(
      page.locator('#packet-rows tr[data-number="2"] td[data-field="info"] .value-text'), 'SYN');
    await page.mouse.click(andPoint.x, andPoint.y, {button: 'right'});
    await page.getByRole('menuitem', {name: '選択部分を含む条件をANDで追加', exact: true}).click();
    await waitNumbers([2,6]);
    await waitReady();
    assert.match(await page.locator('#active-filters').textContent(), /AND/);
    const orPoint = await selectText(
      page.locator('#packet-rows tr[data-number="2"] td[data-field="protocol"] .value-text'), 'TCP');
    await page.mouse.click(orPoint.x, orPoint.y, {button: 'right'});
    await page.getByRole('menuitem', {name: '選択部分を含む条件をORで追加', exact: true}).click();
    await waitNumbers([2,4,6]);
    await waitReady();
    assert.match(await page.locator('#active-filters').textContent(), /OR/);
    await clearFilters();
    await page.locator('#close-filter').click();
    // String selection within the protocol tree is quiet too; right-click uses the field type.
    const dnsName = page.locator('.field-row[data-field="dns.qry.name"] .detail-value').first();
    await dnsName.evaluate(node => {
      for (let ancestor = node.parentElement; ancestor; ancestor = ancestor.parentElement) {
        if (ancestor.tagName === 'DETAILS') ancestor.open = true;
      }
    });
    const detailPoint = await selectText(dnsName, 'example.com');
    await page.mouse.click(detailPoint.x, detailPoint.y, {button:'right'});
    await page.getByRole('menuitem', {name:'選択文字列を含む', exact:true}).click();
    await waitNumbers([1,5]); await waitReady();
    assert.match(await page.locator('#active-filters').textContent(), /dns.qry.name/);
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

    const pinNumbers = () => page.evaluate(() => window.PacketApp.state.pins.map(pin => pin.number));
    await realRows().nth(1).locator('td[data-field="number"]').click();
    await page.waitForFunction(() => window.PacketApp.state.selectedDetail?.number === 2);
    assert.deepEqual(await pinNumbers(), []); // A single click still only inspects.
    await realRows().nth(1).locator('td[data-field="source"]').dblclick();
    await page.waitForFunction(() => window.PacketApp.state.pins.length === 1);
    assert.deepEqual(await pinNumbers(), [2]);
    // The same gesture never removes an existing pin or creates duplicate snapshots.
    await realRows().nth(1).locator('td[data-field="source"]').dblclick();
    assert.deepEqual(await pinNumbers(), [2]);
    await realRows().nth(3).locator('td[data-field="info"]').dblclick();
    await page.waitForFunction(() => window.PacketApp.state.pins.length === 2);
    assert.deepEqual(await pinNumbers(), [2,4]);
    await page.waitForFunction(() => window.PacketApp.state.selectedDetail?.number === 4);
    await page.screenshot({path: 'artifacts/double-click-pins.png'});
    // Pins survive filtering and remain inspectable while the row itself is hidden.
    await realRows().first().locator('td[data-field="protocol"]').click({button:'right'});
    await page.getByRole('menuitem', {name:'この値だけ表示', exact:true}).click();
    await waitNumbers([1,5]);
    assert.deepEqual(await pinNumbers(), [2,4]);
    await page.reload({waitUntil:'networkidle'});
    await waitNumbers([1,5]); await waitReady();
    assert.deepEqual(await pinNumbers(), [2,4]);
    await clearFilters(); await page.locator('#close-filter').click();
    // Explicit pin buttons still remove/add a pin once; no row double-click handler runs.
    await realRows().nth(1).locator('.pin-button').click();
    assert.deepEqual(await pinNumbers(), [4]);
    await realRows().nth(1).locator('.pin-button').click();
    assert.deepEqual(await pinNumbers(), [4,2]);
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
    console.log("Browser smoke passed: context-only text selection, double-click pinning, persistence, continuous list and comparison");
  } catch (error) {
    await page.screenshot({path:'artifacts/interaction-failure.png'}).catch(() => {});
    fs.writeFileSync('artifacts/interaction-failure.txt', String(error) + '\n' + JSON.stringify(errors));
    throw error;
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
