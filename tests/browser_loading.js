/* Delay real HTTP requests (not fake analysis results) to inspect each busy state. */
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:900}});
  const page = await context.newPage(), errors = [], releases = [];
  page.setDefaultTimeout(20000);
  page.on('pageerror', error => errors.push(error.message));
  let armed = null;
  function hold(match) {
    assert.equal(armed,null);
    let entered,release;
    let timer;
    const reached = new Promise((resolve,reject) => {
      entered=()=>{clearTimeout(timer);resolve();};
      timer=setTimeout(()=>reject(new Error('Timed out waiting for a real request')),20000);
    });
    const wait = new Promise(resolve => release=resolve);
    armed = {match,wait,entered}; releases.push(release);
    return {reached,release};
  }
  await context.route('**/api/**', async route => {
    const request=route.request(), gate=armed;
    if(gate && gate.match(request)) {armed=null;gate.entered();await gate.wait;}
    await route.continue().catch(()=>{}); // Closing a view may abort a held request.
  });
  const job = (operation,number) => request => request.method()==='POST' && request.url().endsWith('/jobs') &&
    request.postDataJSON().operation===operation && (number===undefined || request.postDataJSON().payload.number===number);
  const scope = name => `[data-loading-scope="${name}"]`;
  const busy = name => page.locator(`${scope(name)}[data-loading-state="busy"] .loading-mask`).first();
  const shot = async name => {
    assert.equal(await page.locator('.loading-elapsed').count(), 0);
    assert.doesNotMatch((await page.locator('.loading-mask').allTextContents()).join('\n'), /経過\s*\d+\s*秒/);
    return page.screenshot({path:`artifacts/loading-${name}.png`});
  };
  async function idle() {
    await page.waitForFunction(()=>!document.body.classList.contains('has-pending'));
    assert.equal(await page.locator('.loading-surface[data-loading-state="busy"]').count(),0);
  }
  async function ready(number) {
    await page.waitForFunction(n=>window.PacketApp.state.selectedDetail?.number===n && document.querySelector('.hex-byte'),number);
    await idle();
  }
  async function inspect(number) {
    await page.locator(`#packet-rows tr[data-number="${number}"] td[data-field="number"]`).click();
  }
  try {
    await page.goto('http://127.0.0.1:18080/',{waitUntil:'networkidle'});
    const upload=hold(r=>r.method()==='POST' && r.url().endsWith('/api/instances'));
    await page.locator('#file-input').setInputFiles(path.resolve('artifacts/inspection.pcap'));
    await upload.reached; await busy('packets').waitFor();
    assert.match(await busy('packets').textContent(),/解析データを送信中/);
    assert.equal(await page.locator('#packet-scroll').getAttribute('aria-busy'),'true');
    assert.equal(await page.locator('#close-capture').isEnabled(),true);
    assert.equal(await page.locator('#selection-tools').count(),0);
    // Cross the former one-second tick while the real upload remains held.
    await page.waitForTimeout(1200);
    assert.equal(await busy('packets').locator('.loading-spinner').isVisible(), true);
    assert.match(await busy('packets').textContent(), /解析データを送信中/);
    assert.doesNotMatch(fs.readFileSync('static/app/loading.js', 'utf8'), /loading-elapsed|\b(?:setInterval|clearInterval)\s*\(/);
    assert.doesNotMatch(fs.readFileSync('static/style.css', 'utf8'), /loading-elapsed/);
    await shot('upload');
    upload.release(); await ready(1);

    const slow=hold(job('detail',3));
    await inspect(3);await slow.reached;await busy('detail').waitFor();
    assert.equal(await page.locator(`${scope('detail')}[data-loading-state="busy"]`).count(),2);
    assert.equal(await page.locator('#packet-details').getAttribute('aria-busy'),'true');
    // Details load independently; the packet list is still usable.
    assert.equal(await page.locator('#packet-scroll').evaluate(node=>node.inert),false);
    assert.equal(await busy('detail').locator('.skeleton-frame').isVisible(),true);
    assert.equal(await busy('detail').locator('.loading-spinner').isVisible(),false);
    await shot('detail');slow.release();await ready(3);

    // A cancelled older selection must not hide the current selection's spinner.
    const old=hold(job('detail',2));await inspect(2);await old.reached;
    const newer=hold(job('detail',7));await inspect(7);await newer.reached;
    old.release();await busy('detail').waitFor();
    assert.match(await busy('detail').textContent(),/#7/);
    newer.release();await ready(7);

    await page.locator('#packet-rows tr[data-number="2"] td[data-field="info"]').dblclick();await ready(2);
    await page.locator('#packet-rows tr[data-number="7"] td[data-field="info"]').dblclick();await ready(7);
    await page.evaluate(()=>window.PacketApp.state.compareDetails.clear());
    const compare=hold(job('detail',2));
    await page.locator('#compare-pins').click();await compare.reached;await busy('compare').waitFor();
    await shot('comparison');
    await page.locator('#close-compare').click();compare.release();await idle();
    await page.locator('#compare-pins').click();
    await page.locator('#compare-table td.different').first().waitFor();await idle();
    await page.locator('#close-compare').click();

    const relations=hold(job('relations',7));
    await page.locator('#open-relations').click();await relations.reached;await busy('relations').waitFor();
    await shot('relations');relations.release();
    await page.locator('.relation-record[data-number="8"]').waitFor();await idle();
    await page.locator('#close-relations').click();

    const filter=hold(job('packets'));
    await page.locator('#toggle-filter').click();
    await page.locator('.advanced-filter').evaluate(node=>node.open=true);
    await page.locator('#raw-filter').fill('tcp && (');await page.locator('#apply-filters').click();
    await filter.reached;await busy('packets').waitFor();await shot('filter');filter.release();
    await page.locator(`${scope('packets')}[data-loading-state="error"] .loading-message`).waitFor();
    await idle();
    assert.equal(await page.locator('#packet-scroll').getAttribute('aria-busy'),'false');
    assert.equal(await page.locator(`${scope('packets')} .loading-spinner`).isVisible(),false);
    await shot('error');
    await page.locator('#clear-filters').click();await ready(1);await page.locator('#close-filter').click();

    // Closing the file aborts outstanding UI requests without trapping the spinner.
    const closing=hold(job('detail',3));await inspect(3);await closing.reached;
    await page.locator('#close-capture').click();closing.release();await idle();
    assert.equal(await page.locator('#packet-rows tr[data-number]').count(),0);
    await page.locator('.capture-open').click();await ready(1);
    const mobile=hold(job('detail',3));
    await page.setViewportSize({width:390,height:844});await page.locator('#font-size').selectOption('14');
    await page.emulateMedia({reducedMotion:'reduce'});
    await inspect(3);await mobile.reached;await busy('detail').waitFor();
    assert.equal(await page.locator(`${scope('detail')} .loading-spinner`).first().evaluate(n=>getComputedStyle(n).animationName),'none');
    for (const mask of await page.locator(`${scope('detail')} .loading-mask`).all()) {
      const r=await mask.boundingBox();assert(r && r.x>=0 && r.x+r.width<=391 && r.y+r.height<=844);
    }
    await shot('mobile');mobile.release();await ready(3);
    assert.deepEqual(errors,[]);
    fs.writeFileSync('artifacts/loading-checks.json',JSON.stringify({realResponses:true,
      elapsedTimeRemoved:true,stages:true,staleRequests:true,closeDuringLoad:true,errorThenRetry:true,
      comparison:true,relations:true,mobile:true,reducedMotion:true,errors},null,2));
    console.log('Loading states passed: delayed real requests, stale completion, errors, close, mobile');
  } catch(error) {
    await shot('failure').catch(()=>{});
    fs.writeFileSync('artifacts/loading-failure.txt',String(error)+'\n'+JSON.stringify(errors));throw error;
  } finally {releases.forEach(release=>release());await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
