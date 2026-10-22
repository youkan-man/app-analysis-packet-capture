/* Actual Linux host loopback -> dumpcap sidecar -> browser IndexedDB -> TShark.
 * Only the CI UDP fixture's port is captured. No external traffic or mocked packets.
 */
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch({headless: true});
  const a = await browser.newContext({viewport: {width: 1440, height: 900}});
  const b = await browser.newContext({viewport: {width: 1440, height: 900}});
  const page = await a.newPage(), other = await b.newPage();
  const errors = [], sessions = [];
  page.setDefaultTimeout(30000);
  page.on('pageerror', error => errors.push(error.message));
  other.on('pageerror', error => errors.push(error.message));
  a.on('response', async response => {
    if (response.url().endsWith('/api/live/sessions') && response.request().method() === 'POST' && response.status() === 201) {
      sessions.push({id: (await response.json()).id, auth: (await response.request().allHeaders()).authorization});
    }
  });
  const origin = 'http://127.0.0.1:18080';
  const shot = name => page.screenshot({path: 'artifacts/capture-' + name + '.png'});
  async function eventually(fn) {
    for (let i=0;i<150;i++) {if (await fn()) return; await new Promise(resolve => setTimeout(resolve,100));}
    throw new Error('Capture state transition did not occur');
  }
  async function configure(port=49321) {
    await page.locator('#open-live').click();
    await page.waitForFunction(() => document.querySelector('#live-start').disabled === false);
    await page.locator('#live-interface').selectOption('lo');
    await page.locator('#live-protocol').selectOption('udp');
    await page.locator('#live-host').fill('127.0.0.1');
    await page.locator('#live-port').fill(String(port));
    await page.locator('#live-duration').fill('60');
  }
  async function ready() {
    await page.waitForFunction(() => window.PacketApp.state.selectedDetail?.fields?.length &&
      document.querySelector('.hex-byte') && !document.body.classList.contains('has-pending'));
  }
  async function assertUdp(port) {
    const values = await page.evaluate(() => window.PacketApp.state.packets.map(p => ({protocol: p.protocol, source: p.source, port: p.fields['udp.dstport']})));
    assert(values.length > 0);
    assert(values.every(p => p.protocol === 'UDP' && p.source === '127.0.0.1' && p.port === String(port)));
  }
  try {
    await page.goto(origin, {waitUntil: 'networkidle'});
    await other.goto(origin, {waitUntil: 'networkidle'});
    await configure();
    await shot('setup');
    await page.locator('#live-start').click();
    await eventually(() => sessions.length === 1);
    await page.waitForFunction(() => /取得中.*lo/.test(document.querySelector('#live-status').textContent));
    const own = sessions[0], url = origin + '/api/live/sessions/' + own.id;
    const foreign = {Authorization: 'Bearer ' + 'f'.repeat(64)};
    assert.equal((await b.request.get(url, {headers: foreign})).status(),404);
    assert.equal((await b.request.get(url + '/data', {headers: foreign})).status(),404);
    assert.equal((await b.request.post(url + '/stop', {headers: foreign})).status(),404);
    assert.equal((await b.request.delete(url, {headers: foreign})).status(),404);
    assert.equal((await b.request.get(origin + '/api/live/sessions', {headers: foreign})).status(),405);
    // An actual capture is writing; filenames/tokens are not exposed to another browser.
    await eventually(async () => (await (await a.request.get(url, {headers: {Authorization: own.auth}})).json()).bytes > 100);
    assert.doesNotMatch(await page.locator('#live-dialog').textContent(), /経過\s*\d+秒/);
    await shot('recording');
    await page.locator('#live-close').click();
    assert.equal(await page.locator('#open-file').isEnabled(),true);
    assert.match(await page.locator('#open-live').textContent(), /キャプチャ中/);
    await page.locator('#open-live').click();
    await page.locator('#live-save').click();
    await page.locator('#live-dialog').waitFor({state:'hidden'});
    await ready(); await assertUdp(49321);
    assert.equal(await page.locator('.capture-item').count(),1);
    assert.equal(await other.locator('.capture-item').count(),0);
    const stored = await page.evaluate(async () => {
      const db = await new Promise((resolve,reject)=>{const r=indexedDB.open('packetcap-local-v1');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
      const id=window.PacketApp.state.active.id;
      const blob=await new Promise(resolve=>{const r=db.transaction('files').objectStore('files').get(id);r.onsuccess=()=>resolve(r.result);});
      db.close();return {bytes:blob.size,magic:Array.from(new Uint8Array(await blob.slice(0,4).arrayBuffer())),settings:JSON.stringify(localStorage)};
    });
    assert(stored.bytes > 100);assert.deepEqual(stored.magic,[10,13,13,10]);
    assert(!stored.settings.includes(own.auth.slice(7)));
    assert.equal((await a.request.get(url, {headers:{Authorization:own.auth}})).status(),404);
    await shot('saved-analysis');
    await page.reload({waitUntil:'networkidle'});await ready();await assertUdp(49321);
    // The packet limit closes the real dumpcap process and imports automatically.
    await configure(49322);
    await page.locator('.live-advanced').evaluate(n=>n.open=true);
    await page.locator('#live-packets').fill('12');
    await page.locator('#live-start').click();
    await page.locator('#live-dialog').waitFor({state:'hidden'});await ready();await assertUdp(49322);
    assert.equal(await page.locator('.capture-item').count(),2);
    assert.equal(await page.evaluate(()=>window.PacketApp.state.total),12);
    // Discard is explicitly confirmed and never adds a local source.
    await configure();await page.locator('#live-packets').fill('100000');
    await page.locator('#live-start').click();
    await page.waitForFunction(()=>!document.querySelector('#live-discard').disabled && !document.querySelector('#live-discard').hidden);
    page.once('dialog',dialog=>dialog.accept());await page.locator('#live-discard').click();
    await page.waitForFunction(()=>!document.querySelector('#live-start').hidden && !document.querySelector('#live-start').disabled);
    assert.equal(await page.locator('.capture-item').count(),2);
    // Invalid BPF comes back as a genuine dumpcap failure and can be discarded.
    await page.locator('#live-bpf').fill('udp and (');await page.locator('#live-start').click();
    await page.locator('#live-status.is-error').waitFor();
    assert.equal(await page.locator('#open-live').textContent(),'取得エラー');
    assert.equal(await page.locator('#live-save').isDisabled(),true);
    await shot('invalid-filter');
    page.once('dialog',dialog=>dialog.accept());await page.locator('#live-discard').click();
    await page.waitForFunction(()=>!document.querySelector('#live-start').hidden && !document.querySelector('#live-start').disabled);
    await page.locator('#live-bpf').fill('');
    await page.setViewportSize({width:390,height:844});
    await page.locator('#live-close').click();
    await page.locator('#font-size').selectOption('14');
    await page.locator('#open-live').click();
    await page.waitForFunction(()=>!document.querySelector('#live-start').disabled);
    const box=await page.locator('#live-dialog').boundingBox();
    assert(box.x>=0 && box.x+box.width<=391 && box.y>=0 && box.y+box.height<=844);
    await shot('mobile');
    // Real default deployment has no capture privileges and presents an actionable state.
    const disabled=await a.newPage();await disabled.goto('http://127.0.0.1:18082/',{waitUntil:'networkidle'});
    await disabled.locator('#open-live').click();
    await disabled.locator('#live-status.is-error').waitFor();
    assert.equal(await disabled.locator('#live-start').isDisabled(),true);
    assert.equal(await disabled.locator('#live-options').evaluate(node => node.disabled),true);
    for (const id of ['live-interface','live-protocol','live-port','live-host']) {
      assert.equal(await disabled.locator('#' + id).isDisabled(),true);
    }
    await disabled.screenshot({path:'artifacts/capture-disabled.png'});
    assert.deepEqual(errors,[]);
    fs.writeFileSync('artifacts/live-capture-checks.json',JSON.stringify({
      realDumpcap:true,hostLoopbackOnly:true,manualStop:true,packetLimit:true,
      indexedDB:true,reload:true,foreignRead:404,foreignStop:404,foreignDelete:404,
      discardedNotSaved:true,invalidBpf:true,mobile:true,defaultDisabled:true,errors},null,2));
    console.log('Live capture passed: actual host-loopback UDP, private sessions, browser save and TShark inspection');
  } catch(error) {await shot('failure').catch(()=>{});throw error;}
  finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
