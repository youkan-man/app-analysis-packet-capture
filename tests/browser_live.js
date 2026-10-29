/* Real dumpcap in the single application container, generated loopback UDP only. */
const {chromium}=require('playwright');
const assert=require('node:assert/strict'),fs=require('node:fs');
const {execFileSync}=require('node:child_process');
const ip=(...args)=>execFileSync('sudo',['ip',...args],{stdio:'pipe'});
(async()=>{
  const browser=await chromium.launch({headless:true});
  const a=await browser.newContext({viewport:{width:1440,height:900},permissions:['clipboard-read','clipboard-write']});
  const b=await browser.newContext({viewport:{width:1440,height:900}});
  const page=await a.newPage(),other=await b.newPage(),errors=[],sessions=[];
  let adapterCreated=false;
  for(const p of [page,other]){p.setDefaultTimeout(30000);p.on('pageerror',e=>errors.push(e.message));}
  a.on('response',async response=>{
    if(response.url().endsWith('/api/live/sessions')&&response.request().method()==='POST'&&response.status()===201)
      sessions.push({id:(await response.json()).id,auth:(await response.request().allHeaders()).authorization});
  });
  const origin='http://127.0.0.1:18080';
  const shot=name=>page.screenshot({path:'artifacts/capture-'+name+'.png'});
  const idle=()=>page.waitForFunction(()=>!document.body.classList.contains('has-pending'));
  async function configure(limit='100000') {
    await page.locator('#open-live').click();
    await page.waitForFunction(()=>!document.querySelector('#live-options').disabled);
    await page.locator('#live-interface').selectOption('lo');
    await page.locator('#live-protocol').selectOption('udp');
    await page.locator('#live-host').fill('127.0.0.1');
    await page.locator('#live-port').fill('49321');
    await page.locator('#live-duration').fill('60');
    await page.locator('.live-advanced').evaluate(n=>n.open=true);
    await page.locator('#live-packets').fill(limit);
  }
  async function key(name) {
    await page.locator('#packet-scroll').press(name);
    await page.waitForFunction(()=>window.PacketApp.state.selectedDetail?.number===window.PacketApp.state.selected);
    await idle();
  }
  try {
    await page.goto(origin,{waitUntil:'networkidle'});await other.goto(origin,{waitUntil:'networkidle'});
    // Hold the actual configuration response to photograph the modal skeleton.
    let release,arrived,handled;
    const resumed=new Promise(r=>handled=r);
    const gate=new Promise(r=>release=r),reached=new Promise(r=>arrived=r);
    await a.route('**/api/live/config',async route=>{arrived();await gate;await route.continue();handled();});
    await page.locator('#open-live').click();await reached;
    assert(await page.locator('#live-config-skeleton').isVisible());
    await shot('config-skeleton');release();await resumed;await a.unroute('**/api/live/config');
    await page.waitForFunction(()=>!document.querySelector('#live-options').disabled);
    for(const id of ['live-duration','live-size','live-packets','live-snaplen'])assert.equal(await page.locator('#'+id).inputValue(),'');
    await page.locator('#live-close').click();
    await configure();await shot('setup');
    await page.locator('#live-start').click();
    await page.locator('#live-dialog').waitFor({state:'hidden'});
    await page.waitForFunction(()=>window.PacketApp.state.captures.length===1);
    const localId=await page.evaluate(()=>window.PacketApp.state.active.id);
    assert.equal(await page.locator('.capture-item').count(),1);
    assert.equal(await other.locator('.capture-item').count(),0);
    await page.waitForFunction(()=>window.PacketApp.state.total>=12);
    await idle();
    const initial=await page.evaluate(()=>window.PacketApp.state.total);
    await page.waitForFunction(n=>window.PacketApp.state.total>n,initial);
    assert.equal(await page.evaluate(()=>window.PacketApp.state.active.id),localId);
    assert.equal(await page.locator('.capture-item').count(),1);
    assert(await page.locator('#stop-live').isVisible());
    assert.match(await page.locator('#open-live').textContent(),/キャプチャ中/);
    assert((await page.evaluate(()=>window.PacketApp.state.packets)).every(p=>p.protocol==='UDP'&&p.fields['udp.dstport']==='49321'));
    const session=sessions[0],url=origin+'/api/live/sessions/'+session.id,foreign={Authorization:'Bearer '+'f'.repeat(64)};
    for(const suffix of ['','/data'])assert.equal((await b.request.get(url+suffix,{headers:foreign})).status(),404);
    assert.equal((await b.request.post(url+'/stop',{headers:foreign})).status(),404);
    assert.equal((await b.request.post(url+'/query',{headers:foreign,data:{operation:'packets',payload:{}}})).status(),404);
    assert.equal((await b.request.delete(url,{headers:foreign})).status(),404);
    await key('Home');await key('ArrowDown');
    assert.equal(await page.evaluate(()=>window.PacketApp.state.selected),2);
    await key(' ');assert(await page.evaluate(()=>window.PacketApp.state.pins.some(p=>p.number===2)));
    await key('Control+c');assert.match(await page.evaluate(()=>navigator.clipboard.readText()),/^2\t/);
    await key('Shift+F10');assert(await page.locator('#context-menu').isVisible());await page.keyboard.press('Escape');
    // Updating records must preserve the selected row, focused element and actual DOM node.
    await page.locator('#packet-rows tr[data-number="2"]').focus();
    await page.evaluate(()=>{window.retainedRow=document.querySelector('#packet-rows tr[data-number="2"]');window.beforeCount=PacketApp.state.total;});
    await page.waitForFunction(()=>PacketApp.state.total>window.beforeCount+2);
    assert(await page.evaluate(()=>retainedRow===document.querySelector('#packet-rows tr[data-number="2"]')));
    assert.equal(await page.evaluate(()=>document.activeElement.dataset.number),'2');
    assert.equal(await page.evaluate(()=>PacketApp.state.selected),2);
    await shot('realtime-keyboard');
    await key('PageDown');assert(await page.evaluate(()=>PacketApp.state.selected>2));
    await key('End');const end=await page.evaluate(()=>PacketApp.state.selected);
    await key('ArrowUp');assert.equal(await page.evaluate(()=>PacketApp.state.selected),end-1);
    await page.waitForFunction(()=>PacketApp.state.total>60);
    await key('End');
    const scrolled=await page.evaluate(()=>{window.retainedRow=document.activeElement;window.beforeCount=PacketApp.state.total;return{selected:PacketApp.state.selected,top:document.querySelector('#packet-scroll').scrollTop};});
    assert(scrolled.top>0);
    await page.waitForFunction(()=>PacketApp.state.total>window.beforeCount+2);
    assert(await page.evaluate(()=>document.activeElement===retainedRow));
    assert.equal(await page.evaluate(()=>PacketApp.state.selected),scrolled.selected);
    assert.equal(await page.locator('#packet-scroll').evaluate(n=>n.scrollTop),scrolled.top);
    await key('Home');assert.equal(await page.evaluate(()=>PacketApp.state.selected),1);
    // The current filter is reapplied to growing data, rather than silently cleared.
    await page.locator('#toggle-filter').click();
    await page.locator('.advanced-filter').evaluate(n=>n.open=true);
    await page.locator('#raw-filter').fill('frame.number <= 4');await page.locator('#apply-filters').click();
    await page.waitForFunction(()=>PacketApp.state.matched===4);await idle();
    const filteredTotal=await page.evaluate(()=>PacketApp.state.total);
    await page.waitForFunction(n=>PacketApp.state.total>n,filteredTotal);
    assert.deepEqual(await page.evaluate(()=>PacketApp.state.packets.map(p=>p.number)),[1,2,3,4]);
    await key('End');assert.equal(await page.evaluate(()=>PacketApp.state.selected),4);
    await shot('realtime-filter');
    await page.locator('#clear-filters').click();await idle();await page.locator('#close-filter').click();
    // Stop updates the original file; no second import or selection reset.
    await key('Home');await key('ArrowDown');
    await page.locator('#stop-live').click();await page.locator('#stop-live').waitFor({state:'hidden'});await idle();
    assert.equal(await page.evaluate(()=>PacketApp.state.active.id),localId);
    assert.equal(await page.evaluate(()=>PacketApp.state.selected),2);
    assert.equal(await page.locator('.capture-item').count(),1);
    assert.equal((await a.request.get(url,{headers:{Authorization:session.auth}})).status(),404);
    const total=await page.evaluate(()=>PacketApp.state.total);
    await page.reload({waitUntil:'networkidle'});await page.waitForFunction(n=>PacketApp.state.total===n,total);await idle();
    assert.equal(await page.evaluate(()=>PacketApp.state.active.id),localId);
    assert.equal(await other.locator('.capture-item').count(),0);
    await shot('saved-analysis');
    // Fast automatic stop must also retain exactly one newly created file.
    await configure('12');await page.locator('#live-start').click();await page.locator('#live-dialog').waitFor({state:'hidden'});
    await page.waitForFunction(()=>PacketApp.state.captures.length===2&&PacketApp.state.total===12&&document.querySelector('#stop-live').hidden);
    await idle();assert.equal(await page.locator('.capture-item').count(),2);
    // A third capture can be explicitly discarded without deleting prior captures.
    await configure();await page.locator('#live-start').click();await page.locator('#live-dialog').waitFor({state:'hidden'});
    await page.waitForFunction(()=>PacketApp.state.captures.length===3&&PacketApp.state.total>2);
    await page.locator('#open-live').click();page.once('dialog',d=>d.accept());await page.locator('#live-discard').click();
    await page.waitForFunction(()=>PacketApp.state.captures.length===2);
    await page.locator('#live-close').click();
    // Dynamic catalog refresh must preserve entered settings and detect removed adapters.
    await configure();
    assert.equal(await page.locator('#live-interface option[value="pcana-ci0"]').count(),0);
    ip('link','add','pcana-ci0','type','dummy');adapterCreated=true;ip('link','set','pcana-ci0','up');
    await page.waitForFunction(()=>[...document.querySelector('#live-interface').options].some(o=>o.value==='pcana-ci0'));
    await page.locator('#live-interface').selectOption('pcana-ci0');await page.locator('#live-port').fill('49322');
    await page.locator('#live-reload').click();await page.waitForFunction(()=>!document.querySelector('#live-options').disabled);
    assert.equal(await page.locator('#live-interface').inputValue(),'pcana-ci0');
    assert.equal(await page.locator('#live-port').inputValue(),'49322');await shot('dynamic-network');
    ip('link','del','pcana-ci0');adapterCreated=false;
    await page.waitForFunction(()=>![...document.querySelector('#live-interface').options].some(o=>o.value==='pcana-ci0'));
    assert.equal(await page.locator('#live-interface').inputValue(),'');assert(await page.locator('#live-start').isDisabled());
    await shot('network-removed');await page.locator('#live-close').click();
    await page.setViewportSize({width:390,height:844});await page.locator('#font-size').selectOption('14');
    await page.locator('#open-live').click();await page.waitForFunction(()=>!document.querySelector('#live-options').disabled);
    const box=await page.locator('#live-dialog').boundingBox();assert(box.x>=0&&box.x+box.width<=391&&box.y+box.height<=844);
    assert.doesNotMatch(await page.locator('#live-dialog').textContent(),/Compose|Docker|capture-agent|sidecar|経過/);
    await shot('mobile');
    const unavailable=await b.newPage();await unavailable.goto('http://127.0.0.1:18082/',{waitUntil:'networkidle'});
    await unavailable.locator('#open-live').click();await unavailable.locator('#live-status.is-error').waitFor();
    assert(await unavailable.locator('#live-start').isDisabled());
    assert.doesNotMatch(await unavailable.locator('#live-status').textContent(),/Compose|Docker|dumpcap|NET_RAW|capture-agent/);
    await unavailable.screenshot({path:'artifacts/capture-unavailable.png'});assert.deepEqual(errors,[]);
    fs.writeFileSync('artifacts/live-capture-checks.json',JSON.stringify({integrated:true,realDumpcap:true,createdOnStart:true,
      modalCloses:true,realtimeBeforeStop:true,stableFileId:true,stableSelection:true,stableRow:true,keyboard:true,
      currentFilterRetained:true,skeleton:true,private:true,automaticStop:true,reload:true,dynamicAdapters:true,noFixedLimits:true,errors},null,2));
    console.log('Realtime capture, atomic local append, keyboard and integrated application passed');
  }catch(error){await shot('failure').catch(()=>{});fs.writeFileSync('artifacts/live-failure.txt',String(error)+'\n'+JSON.stringify(errors));throw error;}
  finally{if(adapterCreated){try{ip('link','del','pcana-ci0');}catch{}}await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
