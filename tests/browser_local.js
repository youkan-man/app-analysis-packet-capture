/* Browser-owned data: exercise real IndexedDB, Web Workers and Docker sessions.
 * Capability values are kept in this test's memory and never written to artifacts.
 */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
(async()=>{
  const browser=await chromium.launch({headless:true});
  const a=await browser.newContext({viewport:{width:1440,height:900}});
  const b=await browser.newContext({viewport:{width:1440,height:900}});
  const pageA=await a.newPage(),pageB=await b.newPage();
  const errors=[],leasesA=[],leasesB=[];
  for(const page of [pageA,pageB])page.on('pageerror',error=>errors.push(error.message));
  function collect(context,leases){
    context.on('response',async response=>{
      if(response.url().endsWith('/api/instances')&&response.request().method()==='POST'&&response.status()===201){
        const data=await response.json();
        leases.push({id:data.id,auth:(await response.request().allHeaders()).authorization});
      }
    });
  }
  collect(a,leasesA);collect(b,leasesB);
  const origin='http://127.0.0.1:18080';
  const ready=(page,total)=>page.waitForFunction(n=>window.PacketApp.state.total===n&&
    window.PacketApp.state.selectedDetail?.fields?.length&&document.querySelector('.hex-byte')&&
    !document.querySelector('#status-dot').classList.contains('busy'),total,{timeout:30000});
  async function eventually(fn){
    for(let i=0;i<80;i++){if(await fn())return;await new Promise(r=>setTimeout(r,100));}
    throw new Error('Expected lifecycle transition did not occur');
  }
  try{
    await pageA.goto(origin,{waitUntil:'networkidle'});
    await pageB.goto(origin,{waitUntil:'networkidle'});
    assert.equal(await pageA.locator('.capture-item').count(),0);
    assert.equal(await pageB.locator('.capture-item').count(),0);
    await pageA.locator('#file-input').setInputFiles({name:'browser-A.pcap',mimeType:'application/octet-stream',buffer:fs.readFileSync('artifacts/test.pcap')});
    await ready(pageA,7);
    await eventually(()=>leasesA.length===1);
    await pageB.reload({waitUntil:'networkidle'});
    assert.equal(await pageB.locator('.capture-item').count(),0);
    assert.equal((await b.request.get(origin+'/api/captures')).status(),404);
    assert.equal((await b.request.get(origin+'/api/instances')).status(),405);
    await pageB.locator('#file-input').setInputFiles({name:'browser-B.pcap',mimeType:'application/octet-stream',buffer:fs.readFileSync('artifacts/inspection.pcap')});
    await ready(pageB,10);await eventually(()=>leasesB.length===1);
    assert.deepEqual(await pageA.locator('.capture-open strong').allTextContents(),['browser-A.pcap']);
    assert.deepEqual(await pageB.locator('.capture-open strong').allTextContents(),['browser-B.pcap']);
    const firstA=leasesA[0],firstB=leasesB[0],aUrl=origin+'/api/instances/'+firstA.id;
    const own={Authorization:firstA.auth},foreign={Authorization:firstB.auth};
    assert.notEqual(firstA.id,firstB.id);
    assert.notEqual(firstA.auth,firstB.auth);
    assert.equal((await b.request.get(aUrl)).status(),404);
    assert.equal((await b.request.get(aUrl,{headers:foreign})).status(),404);
    assert.equal((await b.request.delete(aUrl,{headers:foreign})).status(),404);
    assert.equal((await b.request.post(aUrl+'/jobs',{headers:foreign,data:{operation:'packets',payload:{}}})).status(),404);
    const job=await a.request.post(aUrl+'/jobs',{headers:own,data:{operation:'packets',payload:{}}});
    assert.equal(job.status(),202);
    const jobUrl=aUrl+'/jobs/'+(await job.json()).id;
    assert.equal((await b.request.get(jobUrl,{headers:foreign})).status(),404);
    assert.equal((await b.request.delete(jobUrl,{headers:foreign})).status(),404);
    let result;
    await eventually(async()=>{result=await(await a.request.get(jobUrl,{headers:own})).json();return result.state==='done';});
    assert.equal(result.result.total,7);
    await a.request.delete(jobUrl,{headers:own});
    // A private instance handles all detail/filter/relationship operations without new uploads.
    await pageA.locator('#packet-rows tr[data-number="2"] td[data-field="number"]').click();
    await pageA.waitForFunction(()=>window.PacketApp.state.selectedDetail?.number===2);
    assert.equal(leasesA.length,1);
    const storage=await pageA.evaluate(async()=>{
      const database=await new Promise((resolve,reject)=>{const r=indexedDB.open('packetcap-local-v1');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
      const id=window.PacketApp.state.active.id;
      const blob=await new Promise((resolve,reject)=>{const r=database.transaction('files').objectStore('files').get(id);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
      database.close();
      return {bytes:blob.size,magic:Array.from(new Uint8Array(await blob.slice(0,4).arrayBuffer())),settings:JSON.stringify(localStorage)};
    });
    assert.equal(storage.bytes,fs.statSync('artifacts/test.pcap').size);
    assert.deepEqual(storage.magic,[0xd4,0xc3,0xb2,0xa1]);
    assert(!storage.settings.includes(firstA.auth.slice(7)));
    await pageA.screenshot({path:'artifacts/browser-local-A.png'});
    await pageB.screenshot({path:'artifacts/browser-local-B.png'});

    // Refresh drops ephemeral capabilities but reopens the original local file.
    await pageA.reload({waitUntil:'networkidle'});await ready(pageA,7);
    await eventually(()=>leasesA.length>=2);
    assert.notEqual(leasesA.at(-1).id,firstA.id);
    assert.equal(await pageA.locator('.capture-item').count(),1);
    // Expire this handle (equivalent to a lost/restarted worker) and recover from IndexedDB.
    const expired=leasesA.at(-1);
    await a.request.delete(origin+'/api/instances/'+expired.id,{headers:{Authorization:expired.auth}});
    await pageA.locator('#packet-rows tr[data-number="2"] td[data-field="number"]').click();
    await pageA.waitForFunction(()=>window.PacketApp.state.selectedDetail?.number===2);
    await eventually(()=>leasesA.at(-1).id!==expired.id);
    assert.equal(await pageA.locator('.capture-item').count(),1);

    // Actual Docker restart: neither browser's persistent source disappears.
    execFileSync('docker',['restart','packet-workbench-ci'],{stdio:'pipe'});
    await eventually(async()=>{try{return(await a.request.get(origin+'/healthz')).ok();}catch{return false;}});
    await pageA.locator('#refresh').click();await ready(pageA,7);
    await pageB.locator('#refresh').click();await ready(pageB,10);
    assert.deepEqual(await pageA.locator('.capture-open strong').allTextContents(),['browser-A.pcap']);
    assert.deepEqual(await pageB.locator('.capture-open strong').allTextContents(),['browser-B.pcap']);

    // Parallel queued analysis leaves both the UI event loop and other browser responsive.
    await pageA.evaluate(()=>{window.uiTicks=0;window.tick=setInterval(()=>window.uiTicks++,10);});
    const jobs=pageA.evaluate(async()=>{
      const A=window.PacketApp;
      return await Promise.all(Array.from({length:4},()=>A.local.query(A.state.active.id,'packets',{raw:'tcp'})));
    });
    assert.equal((await b.request.get(origin+'/healthz')).status(),200);
    await pageB.locator('#packet-rows tr[data-number="3"] td[data-field="number"]').click();
    await pageB.waitForFunction(()=>window.PacketApp.state.selectedDetail?.number===3);
    assert((await jobs).every(result=>result.matched===3));
    assert(await pageA.evaluate(()=>{clearInterval(window.tick);return window.uiTicks;})>0);

    const lastA=leasesA.at(-1);
    await pageA.locator('#close-capture').click();
    assert.equal(await pageA.locator('.capture-item').count(),1);
    assert.equal(await pageA.locator('#packet-rows tr[data-number]').count(),0);
    await eventually(async()=>(await a.request.get(origin+'/api/instances/'+lastA.id,{headers:{Authorization:lastA.auth}})).status()===404);
    assert.equal(await pageB.locator('.capture-item').count(),1);
    await pageA.locator('.capture-open').click();await ready(pageA,7);
    // Local deletion must still work while this browser cannot reach the server.
    await a.setOffline(true);
    pageA.once('dialog',dialog=>dialog.accept());
    await pageA.locator('.remove-capture').click();
    await pageA.waitForFunction(()=>window.PacketApp.state.captures.length===0);
    await a.setOffline(false);
    await pageA.reload({waitUntil:'networkidle'});
    assert.equal(await pageA.locator('.capture-item').count(),0);
    assert.equal(await pageB.locator('.capture-item').count(),1);
    await pageA.screenshot({path:'artifacts/browser-local-deleted.png'});
    await pageB.setViewportSize({width:390,height:844});
    await pageB.screenshot({path:'artifacts/browser-local-mobile.png'});
    assert.deepEqual(errors,[]);
    fs.writeFileSync('artifacts/browser-local-checks.json',JSON.stringify({
      isolatedBrowsers:true,foreignRead:404,foreignDelete:404,foreignJob:404,
      localBlobVerified:true,capabilityNotPersisted:true,sameInstanceForQueries:true,
      restartRecovered:true,closeReleasesInstance:true,localDeleteIsolated:true,offlineDelete:true,errors,
    },null,2));
    console.log('Browser-local isolation and real Docker restart passed');
  }catch(error){await pageA.screenshot({path:'artifacts/browser-local-failure.png'}).catch(()=>{});throw error;}
  finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
