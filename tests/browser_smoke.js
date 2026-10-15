/* Run real Chromium interactions and save reviewable UI evidence. */
const { chromium } = require("playwright");
const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert/strict");

(async () => {
  fs.mkdirSync("artifacts", { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  try {
    await page.goto("http://127.0.0.1:18080/", { waitUntil: "networkidle" });
    await page.locator("#file-input").setInputFiles(path.resolve("artifacts/test.pcap"));
    await page.locator("#packet-rows tr").first().waitFor();
    assert.equal(await page.locator("#packet-rows tr").count(), 2);
    await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });
    await page.screenshot({ path: "artifacts/packets-desktop.png", fullPage: true });

    await page.locator("#toggle-builder").click();
    await page.locator("#condition-root .rule-value").fill("192.0.2.10");
    await page.locator("#apply-builder").click();
    await page.waitForFunction(() => {
      const rows = document.querySelectorAll("#packet-rows tr");
      return rows.length === 1 && rows[0].querySelector("td")?.textContent === "1";
    });
    assert.equal(await page.locator("#packet-rows tr").count(), 1);
    assert.match(await page.locator("#display-filter").inputValue(), /ip.addr/);
    await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });
    await page.screenshot({ path: "artifacts/filter-builder-desktop.png", fullPage: true });

    await page.locator("#close-builder").click();
    await page.locator("#display-filter").fill("tcp.port == 443");
    await page.locator("#filter-form button[type=submit]").click();
    await page.waitForFunction(() => {
      const rows = document.querySelectorAll("#packet-rows tr");
      return rows.length === 1 && rows[0].querySelector("td")?.textContent === "2";
    });
    assert.equal(await page.locator("#packet-rows tr").count(), 1);
    await page.locator("#packet-bytes .hex-row").first().waitFor({ timeout: 15000 });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: "artifacts/packets-mobile.png", fullPage: true });
    console.log("Browser smoke: PCAP, visual/raw filters and screenshots OK");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
