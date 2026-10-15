/* Real Chromium clipboard, linked-field, split-pane and flow-hierarchy journeys. */
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  fs.mkdirSync('artifacts',{recursive:true});
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1440,height:900}, permissions:['clipboard-read','clipboard-write']});
  const page = await context.newPage();
  const errors=[]; page.on('pageerror',error=>errors.push(error.message));
  page.setDefaultTimeout(20000);
  const field = name => page.locator(`.field-row[data-field="${name}"]`).first();
  const byte = offset => page.locator(`.hex-byte[data-offset="${offset}"]`);
  const readClipboard = () => page.evaluate(()=>navigator.clipboard.readText());
  async function ready(number) {
    await page.waitForFunction(n=>window.PacketApp.state.selectedDetail?.number===n && document.querySelector('.hex-byte'),number);
    await field('ip.src').waitFor();
  }
  async function drag(id,dx,dy) {
    const r=await page.locator(id).boundingBox(); assert(r);
    const x=r.x+r.width/2,y=r.y+r.height/2;
    await page.mouse.move(x,y); await page.mouse.down(); await page.mouse.move(x+dx,y+dy,{steps:8}); await page.mouse.up();
  }
  try {
    await page.goto('http://127.0.0.1:18080/',{waitUntil:'networkidle'});
    await page.locator('#file-input').setInputFiles(path.resolve('artifacts/inspection.pcap'));
    await ready(1);
    assert.equal(await page.evaluate(()=>getComputedStyle(document.documentElement).fontSize),'12px');
    assert.equal(await page.locator('.packet-table').evaluate(node=>getComputedStyle(node).fontSize),'11px');
    await field('ip.src').click();
    assert.equal(await page.locator('.hex-byte.byte-selected').count(),4);
    assert.equal(await page.locator('.ascii-byte.byte-selected').count(),4);
    await page.locator('#copy-bytes').click();
    assert.equal(await readClipboard(),'c0 00 02 0a');
    await page.screenshot({path:'artifacts/linked-bytes-desktop.png'});

    await field('ip.src').click({button:'right'});
    await page.getByRole('menuitem',{name:'値をコピー',exact:true}).click();
    assert.equal(await readClipboard(),'192.0.2.10');
    const display=await field('ip.src').textContent();
    await field('ip.src').click({button:'right'});
    await page.screenshot({path:'artifacts/field-copy-menu.png'});
    await page.getByRole('menuitem',{name:'表示値をコピー',exact:true}).click();
    assert.equal(await readClipboard(),display);
    await field('ip.src').click({button:'right'});
    await page.getByRole('menuitem',{name:'生値（16進）をコピー',exact:true}).click();
    assert.equal((await readClipboard()).toLowerCase(),'c000020a');

    await byte(26).click();
    assert.equal(await page.locator('.selected-field').getAttribute('data-field'),'ip.src');
    await page.locator('.byte-viewport').press('Control+c');
    assert.equal(await readClipboard(),'c0');
    await page.locator('.byte-viewport').press('ArrowRight');
    await page.locator('.byte-viewport').press('Control+c');
    assert.equal(await readClipboard(),'00');
    await page.locator('.byte-viewport').press('Shift+ArrowRight');
    await page.locator('.byte-viewport').press('Control+c');
    assert.equal(await readClipboard(),'00 02');
    const b12=await byte(12).boundingBox(),b13=await byte(13).boundingBox();
    await page.mouse.move(b12.x+2,b12.y+5);await page.mouse.down();
    await page.mouse.move(b13.x+2,b13.y+5,{steps:4});await page.mouse.up();
    await page.locator('#copy-bytes').click();
    assert.equal(await readClipboard(),'08 00');
    await page.locator('.byte-viewport').press('Control+a');
    await page.locator('.byte-viewport').press('Control+c');
    const all=await page.evaluate(()=>window.PacketApp.state.selectedDetail.hex.match(/../g).join(' '));
    assert.equal(await readClipboard(),all);
    if (!(await field('frame').evaluate(node=>node.closest('details').open))) await field('frame').click();
    await field('frame.number').click();
    assert.equal(await page.locator('.hex-byte.byte-selected').count(),0);
    assert.match(await page.locator('#byte-selection').textContent(),/対応バイトなし/);

    const before=await page.locator('.packet-section').evaluate(node=>node.clientHeight);
    await drag('#split-packets',0,-130);
    assert(await page.locator('.packet-section').evaluate(node=>node.clientHeight)<before-80);
    const width=await page.locator('.details-panel').evaluate(node=>node.clientWidth);
    await drag('#split-inspect',-90,0);
    assert(await page.locator('.details-panel').evaluate(node=>node.clientWidth)<width-50);
    await drag('#split-sources',30,0);
    const column=await page.locator('.packet-table th').nth(3).evaluate(node=>node.clientWidth);
    await drag('#resize-column-3',45,0);
    assert(await page.locator('.packet-table th').nth(3).evaluate(node=>node.clientWidth)>column+20);
    await page.locator('#font-size').selectOption('11');
    await page.reload({waitUntil:'networkidle'});await ready(1);
    assert.equal(await page.locator('#font-size').inputValue(),'11');
    assert.equal(await page.evaluate(()=>getComputedStyle(document.documentElement).fontSize),'11px');
    assert(await page.locator('.packet-section').evaluate(node=>node.clientHeight)<before-80);
    await field('ip.src').click();
    await page.screenshot({path:'artifacts/resized-compact-desktop.png'});
    await page.locator('#font-size').selectOption('12');

    await page.locator('#open-relations').click();
    await page.locator('.relation-record[data-number="3"]').waitFor();
    assert.equal(await page.locator('.relation-record').count(),2);
    assert.match(await page.locator('#relations-content').textContent(),/DNS応答/);
    await page.locator('.relation-record[data-number="3"] .relation-jump').click();await ready(3);
    assert.match(await page.locator('.relation-anchor').textContent(),/基準 #1/);
    await page.locator('#close-relations').click();
    await page.locator('#packet-rows tr[data-number="7"] td[data-field="info"]').click({button:'right'});
    await page.getByRole('menuitem',{name:'送受信の階層を解析',exact:true}).click();
    await page.locator('.relation-record[data-number="8"]').waitFor();
    assert.equal(await page.locator('.relation-record').count(),6);
    assert.equal(await page.locator('.relation-record[data-number="10"]').count(),0);
    assert.match(await page.locator('#relations-content').textContent(),/HTTP応答/);
    assert.match(await page.locator('#relations-content').textContent(),/TCP ACK/);
    await page.locator('.relation-record[data-number="7"] .relation-jump').click();await ready(7);
    await page.screenshot({path:'artifacts/communication-hierarchy.png'});
    await drag('#split-right',-30,0);
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:'artifacts/communication-mobile.png'});
    await page.locator('#close-relations').click();
    await page.locator('#split-packets').focus();await page.keyboard.press('ArrowUp');
    await page.screenshot({path:'artifacts/inspection-mobile.png'});
    assert.deepEqual(errors,[]);
    console.log('Inspection journeys passed: clipboard, byte-field linkage, generated fields, resizes, persisted font, DNS/HTTP/ACK hierarchy');
  } catch(error) {
    await page.screenshot({path:'artifacts/inspection-failure.png'}).catch(()=>{});
    fs.writeFileSync('artifacts/inspection-failure.txt',String(error)+'\n'+JSON.stringify(errors));
    throw error;
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
