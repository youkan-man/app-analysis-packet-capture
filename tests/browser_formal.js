/* Real-container visual acceptance for the formal UI; no replacement/mocked API. */
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({headless:true});
  const page = await browser.newPage({viewport:{width:1440,height:900}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.setDefaultTimeout(20000);
  const ready = () => page.waitForFunction(() =>
    !document.querySelector('#status-dot').classList.contains('busy') &&
    document.querySelector('.hex-byte'));
  const field = name => page.locator(`.field-row[data-field="${name}"]`).first();
  const shot = name => page.screenshot({path:`artifacts/formal-${name}.png`});
  try {
    await page.goto('http://127.0.0.1:18080/', {waitUntil:'networkidle'});
    await page.locator('#file-input').setInputFiles(path.resolve('artifacts/lab-inspection.pcap'));
    await page.waitForFunction(() => window.PacketApp.state.total === 84);
    await ready();
    assert.equal(await page.locator('html').evaluate(n=>getComputedStyle(n).colorScheme), 'light');
    assert.equal(await page.locator('.packet-scroll').evaluate(n=>getComputedStyle(n).backgroundColor),'rgb(255, 255, 255)');
    assert.equal(await page.locator('html').evaluate(n=>getComputedStyle(n).fontSize),'12px');
    assert.equal(await page.locator('.packet-table').evaluate(n=>getComputedStyle(n).fontSize),'11px');
    assert.equal(await page.locator('#packet-rows tr[data-number]').first().evaluate(n=>n.getBoundingClientRect().height),24);
    assert.equal(await page.locator('#selection-tools, #prev-page, #next-page, #info-query').count(),0);
    assert.equal(await page.locator('#filter-drawer').isVisible(),false);
    assert(await page.locator('#packet-rows tr[data-number]').count()<84);
    // The visible data still fills the primary area and font geometry is unchanged.
    const metrics = await page.evaluate(() => {
      const rect=s=>document.querySelector(s).getBoundingClientRect().toJSON();
      return {header:rect('.app-header'),list:rect('.packet-section'),details:rect('.inspect-grid'),
        viewport:{width:innerWidth,height:innerHeight},stylesheetCount:document.styleSheets.length};
    });
    assert(metrics.list.height>metrics.details.height);
    assert.equal(metrics.header.height,44);
    assert.equal(metrics.stylesheetCount,1);
    await field('ip.src').click();
    await shot('overview');
    await field('ip.src').click({button:'right'});
    await page.getByRole('menuitem',{name:'値をコピー',exact:true}).waitFor();
    await shot('context-menu');
    await page.keyboard.press('Escape');

    // Reach the final record through continuous scrolling, with no empty viewport.
    await page.locator('#packet-scroll').evaluate(n=>n.scrollTop=n.scrollHeight);
    await page.locator('#packet-rows tr[data-number="84"]').waitFor();
    await page.locator('#packet-scroll').evaluate(n=>n.scrollTop=0);
    await page.locator('#packet-rows tr[data-number="2"]').waitFor();
    await page.locator('#packet-rows tr[data-number="2"] td[data-field="info"]').dblclick();
    await page.locator('#packet-rows tr[data-number="4"] td[data-field="info"]').dblclick();
    await page.waitForFunction(()=>window.PacketApp.state.pins.length===2);
    await page.locator('#compare-pins').click();
    await page.locator('#compare-table td.different').first().waitFor();
    await shot('comparison');
    await page.locator('#close-compare').click();
    await page.locator('#toggle-filter').click();
    await page.locator('#add-condition').click();
    await page.locator('.filter-rule input').fill('TCP');
    await page.locator('#apply-filters').click();
    await page.waitForFunction(()=>window.PacketApp.state.matched===36);
    await ready();
    await shot('filter-drawer');
    await page.locator('#close-filter').click();

    await page.locator('#file-input').setInputFiles(path.resolve('artifacts/inspection.pcap'));
    await page.waitForFunction(()=>window.PacketApp.state.total===10);
    await ready();
    await page.locator('#packet-rows tr[data-number="7"] td[data-field="info"]').click({button:'right'});
    await page.getByRole('menuitem',{name:'送受信の階層を解析',exact:true}).click();
    await page.locator('.relation-record[data-number="8"]').waitFor();
    await page.locator('.relation-record[data-number="7"] .relation-jump').click();
    await page.waitForFunction(()=>window.PacketApp.state.selectedDetail?.number===7);
    await shot('relations');
    await page.locator('#close-relations').click();

    // Every toolbar action remains visible on small screens and at enlarged fonts.
    await page.setViewportSize({width:390,height:844});
    await page.locator('#font-size').selectOption('14');
    for (const id of ['open-file','toggle-filter','open-relations','open-compare','font-size','refresh']) {
      const r = await page.locator('#'+id).boundingBox();
      assert(r && r.x>=0 && r.x+r.width<=391, `${id} must stay inside the viewport`);
    }
    await shot('mobile');
    await page.locator('#toggle-filter').click();
    await page.locator('#add-condition').click();
    for (const node of await page.locator('.filter-rule input,.filter-rule select').all()) {
      const r = await node.boundingBox(); assert(r.x+r.width<=391);
    }
    await shot('mobile-filter');
    assert.deepEqual(errors,[]);
    fs.writeFileSync('artifacts/formal-ui-checks.json',JSON.stringify({metrics,errors,checks:'Light palette; 12/11px; 24px rows; virtual scroll; clipboard menu; pins and comparison; fields; relations; mobile toolbar/form'},null,2));
    console.log('Formal UI checks passed');
  } catch(error) {
    await shot('failure').catch(()=>{});
    fs.writeFileSync('artifacts/formal-ui-failure.txt',String(error)+'\n'+JSON.stringify(errors));
    throw error;
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
