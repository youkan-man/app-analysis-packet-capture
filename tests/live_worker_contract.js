/* Exercise append/stop failure ownership without deleting an uncommitted capture. */
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
  const events=[];let rejectAppend=true,stopped=false,offset=0,number=0;
  const ctx={self:{},AbortController,setTimeout,clearTimeout,
    fetch:async()=>({ok:true,headers:new Map([['X-Capture-Offset',String(offset)],['X-Capture-End','28'],['X-Capture-Available','28']]),
      blob:async()=>new Blob([new Uint8Array(28-offset)])})};
  vm.runInNewContext(fs.readFileSync('static/app/live.worker.js','utf8'),ctx);
  const live=ctx.self.createLiveCapture({
    random:()=> 'a'.repeat(64),
    create:async()=>{events.push('create');return{id:'local',size:28,received:0};},
    notify:e=>events.push(e.type),
    append:async(id,chunk,start)=>{assert.equal(start,0);events.push('append');if(rejectAppend)throw new Error('quota');offset+=chunk.size;return{id,received:offset};},
    mark:async(id,phase)=>{events.push('mark:'+phase);return{id,phase};},
    remove:async()=>events.push('remove'),cleanup:async()=>events.push('delete'),
    remote:async(url)=>{
      if(url.endsWith('/sessions')){events.push('start');number++;return{id:'remote',state:'recording'};}
      if(url.endsWith('/stop'))stopped=true;
      return{id:'remote',state:stopped?'complete':'recording',bytes:28};
    },
  });
  await live.call('start',{interface:'lo'});
  assert.deepEqual(events.slice(0,3),['create','created','start']);
  assert.equal(live.owns('local'),true);
  await assert.rejects(live.call('sync',{}),/quota/);
  assert(!events.includes('delete'));assert.equal(offset,0);
  rejectAppend=false;
  const result=await live.call('sync',{});assert.equal(result.record.id,'local');
  assert.equal(offset,28);assert.equal(number,1);
  const final=await live.call('save',{});assert.equal(final.record.id,'local');
  assert.equal(events.filter(e=>e==='delete').length,1);assert.equal(live.owns('local'),false);
  let started=0;
  const denied=ctx.self.createLiveCapture({
    random:()=> 'a'.repeat(64),create:async()=>{throw new Error('quota');},
    notify:()=>{},append:async()=>{},mark:async()=>{},remove:async()=>{},cleanup:async()=>{},
    remote:async()=>{started++;return{id:'must-not-start'};},
  });
  await assert.rejects(denied.call('start',{interface:'lo'}),error=>error.message==='quota'&&error.capturePending===false);
  await assert.rejects(denied.call('sync',{}),/取得セッション/);
  assert.equal(started,0);
  console.log('Live file creation, append commit and failure retry ownership passed');
})().catch(error=>{console.error(error);process.exit(1);});
