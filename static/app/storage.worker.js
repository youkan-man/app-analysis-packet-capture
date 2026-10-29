/* Browser-owned source files and private background-analysis transport.
 * Blob/IndexedDB I/O, uploads and job polling run off the UI thread.
 * Capabilities live only here, never in URLs, cookies or persistent storage.
 */
'use strict';
const slots = new Map(), requests = new Map();
const random = bytes => Array.from(crypto.getRandomValues(new Uint8Array(bytes)), n => n.toString(16).padStart(2,'0')).join('');
const aborted = () => new DOMException('処理を中止しました', 'AbortError');
let database;
function db() {
  if (!database) database = new Promise((resolve,reject) => {
    const open = indexedDB.open('packetcap-local-v1',1);
    open.onupgradeneeded = () => {
      open.result.createObjectStore('captures',{keyPath:'id'});
      open.result.createObjectStore('files');
    };
    open.onsuccess = () => {
      open.result.onversionchange = () => {open.result.close(); database = null;};
      resolve(open.result);
    };
    open.onerror = () => {database = null; reject(new Error('ブラウザの保存領域を開けません'));};
    open.onblocked = () => {database = null; reject(new Error('別のタブを閉じて保存領域を開き直してください'));};
  });
  return database;
}
async function transaction(stores,mode,build) {
  const connection = await db();
  return new Promise((resolve,reject) => {
    const tx = connection.transaction(stores,mode);
    let result;
    try {result = build(tx);} catch(error) {tx.abort(); reject(error); return;}
    tx.oncomplete = () => resolve(result?.result);
    tx.onabort = () => reject(new Error(tx.error?.name === 'QuotaExceededError'
      ? 'ブラウザの保存容量が不足しています。不要なローカルファイルを削除してください'
      : 'ブラウザのデータ操作に失敗しました。保存領域を確認してください'));
    tx.onerror = () => {}; // onabort is the single failure boundary.
  });
}
async function list() {
  const items = await transaction(['captures'],'readonly',tx=>tx.objectStore('captures').getAll());
  return {items:items.sort((a,b)=>b.added.localeCompare(a.added))};
}
async function store(file,report) {
  report('validating');
  if (!(file instanceof Blob)) throw new Error('ファイルがありません');
  const magic = Array.from(new Uint8Array(await file.slice(0,4).arrayBuffer()),n=>n.toString(16).padStart(2,'0')).join('');
  const formats = {d4c3b2a1:'pcap',a1b2c3d4:'pcap','4d3cb2a1':'pcap',a1b23c4d:'pcap','0a0d0d0a':'pcapng'};
  if (!formats[magic]) throw new Error('PCAP / PCAPNG ファイルではありません');
  const record = {id:random(16),filename:(file.name || 'capture.pcap').replaceAll('\\','/').split('/').pop(),
    size:file.size,format:formats[magic],added:new Date().toISOString()};
  report('saving');
  await transaction(['captures','files'],'readwrite',tx=>{
    tx.objectStore('captures').add(record); tx.objectStore('files').add(file,record.id);
  });
  return record;
}
async function remote(url,options={}) {
  const response = await fetch(url,{cache:'no-store',credentials:'omit',...options});
  if (response.status===204) return null;
  let data;
  try {data=await response.json();} catch {throw new Error('解析サーバーの応答を読み取れません');}
  if (!response.ok) {
    const error=new Error(typeof data.detail==='string'?data.detail:'解析サーバーでエラーが発生しました');
    error.status=response.status; throw error;
  }
  return data;
}
function authorize(slot) {return {Authorization:'Bearer '+slot.token};}
function stage(slot,phase) {slot.phase=phase;slot.listeners.forEach(report=>report(phase));}
function instance(localId) {
  let slot=slots.get(localId);
  if (slot) return slot;
  slot={token:random(32),controller:new AbortController(),id:null,closed:false,phase:'reading',listeners:new Set()};
  slots.set(localId,slot);
  slot.ready=(async()=>{
    const file=await transaction(['files'],'readonly',tx=>tx.objectStore('files').get(localId));
    if (!file) throw new Error('ローカルファイルが見つかりません。もう一度開いてください');
    if (slot.closed) throw aborted();
    stage(slot,'uploading');
    const result=await remote('/api/instances',{method:'POST',headers:{...authorize(slot),'Content-Type':'application/octet-stream'},
      body:file,signal:slot.controller.signal});
    slot.id=result.id; stage(slot,'submitting');
    if (slot.closed) {await release(slot); throw aborted();}
    return slot;
  })().catch(error=>{if(slots.get(localId)===slot)slots.delete(localId);throw error;});
  return slot;
}
async function cleanup(url,slot) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),3000);
  try {await remote(url,{method:'DELETE',headers:authorize(slot),keepalive:true,signal:controller.signal});}
  catch {} // A lost connection is eventually reclaimed by the server lease.
  finally {clearTimeout(timer);}
}
async function release(slot) {
  if(slot.id)await cleanup('/api/instances/'+slot.id,slot);
}
async function close(localId,reason='closed') {
  const slot=slots.get(localId); if(!slot)return;
  slots.delete(localId);slot.closed=true;slot.reason=reason;slot.controller.abort();
  await release(slot);
}
function pause(ms,signal) {
  return new Promise((resolve,reject)=>{
    if(signal.aborted){reject(aborted());return;}
    const finish=()=>{signal.removeEventListener('abort',stop);resolve();};
    const timer=setTimeout(finish,ms);
    function stop(){clearTimeout(timer);reject(aborted());}
    signal.addEventListener('abort',stop,{once:true});
  });
}
async function query(localId,operation,payload,signal,report) {
  for(let attempt=0;attempt<2;attempt++) {
    if(signal.aborted)throw aborted();
    const slot=instance(localId);
    slot.listeners.add(report); report(slot.phase);
    let jobURL;
    try {
      await slot.ready;
      if(signal.aborted||slot.closed)throw aborted();
      slot.listeners.delete(report); report('submitting');
      const base='/api/instances/'+slot.id;
      const job=await remote(base+'/jobs',{method:'POST',headers:{...authorize(slot),'Content-Type':'application/json'},
        body:JSON.stringify({operation,payload}),signal});
      jobURL=base+'/jobs/'+job.id; report('queued');
      let delay=80;
      while(true) {
        const state=await remote(jobURL,{headers:authorize(slot),signal});
        if(state.state==='done')return state.result;
        if(state.state==='error')throw new Error(state.error);
        report(state.state==='queued'?'queued':'running');
        await pause(delay,signal);delay=Math.min(500,delay*1.3);
      }
    } catch(error) {
      if(attempt===0&&!signal.aborted&&(slot.reason==='expired'||
        (error.status===404&&!slot.closed&&slots.get(localId)===slot))) {
        report('reconnecting');
        // Concurrent callers share the replacement; an explicit close never reopens.
        if(slots.get(localId)===slot)await close(localId,'expired');
        continue;
      }
      throw error;
    } finally {
      slot.listeners.delete(report);
      if(jobURL)void cleanup(jobURL,slot);
    }
  }
  throw new Error('解析インスタンスを開き直せませんでした');
}
// An empty PCAPNG section is a valid file even before the first packet arrives.
const emptySection = new Uint8Array([10,13,13,10,28,0,0,0,77,60,43,26,1,0,0,0,255,255,255,255,255,255,255,255,28,0,0,0]);
async function createLive(network) {
  const now=new Date().toISOString();
  const record={id:random(16),filename:'capture-'+network.replace(/[^a-zA-Z0-9_.-]/g,'_')+'-'+now.replace(/[:.]/g,'-')+'.pcapng',
    format:'pcapng',size:emptySection.length,received:0,added:now,phase:'recording'};
  await transaction(['captures','files'],'readwrite',tx=>{
    tx.objectStore('captures').add(record);tx.objectStore('files').add(new Blob([emptySection]),record.id);
  });
  return record;
}
async function updateLive(id,chunk,offset,phase) {
  const connection=await db();
  return new Promise((resolve,reject)=>{
    const tx=connection.transaction(['captures','files'],'readwrite');
    const meta=tx.objectStore('captures').get(id), file=tx.objectStore('files').get(id);
    let done=0,record,failure;
    function write() {
      if(++done!==2)return;
      record=meta.result;
      if(!record || !file.result){failure=new Error('ローカルファイルは削除されています');tx.abort();return;}
      if(chunk) {
        if(record.received!==offset){failure=new Error('保存先の取得位置が一致しません');tx.abort();return;}
        const blob=new Blob(offset?[file.result,chunk]:[chunk],{type:'application/octet-stream'});
        record={...record,size:blob.size,received:offset+chunk.size,phase:'recording'};
        tx.objectStore('files').put(blob,id);
      }
      if(phase)record={...record,phase};
      tx.objectStore('captures').put(record);
    }
    meta.onsuccess=write;file.onsuccess=write;
    tx.oncomplete=()=>resolve(record);
    tx.onabort=()=>reject(failure || new Error('ブラウザに保存できません。空き容量を確認してください'));
    tx.onerror=()=>{};
  });
}
async function removeLocal(id) {
  await transaction(['captures','files'],'readwrite',tx=>{tx.objectStore('captures').delete(id);tx.objectStore('files').delete(id);});
}
importScripts('/static/app/live.worker.js');
const liveCapture = self.createLiveCapture({remote,random,cleanup,create:createLive,
  append:(id,chunk,offset)=>updateLive(id,chunk,offset),mark:(id,phase)=>updateLive(id,null,0,phase),
  remove:removeLocal,notify:event=>self.postMessage({event:'live',...event})});
self.onmessage=async event=>{
  const {id,method,args}=event.data;
  if(method==='cancel'){requests.get(id)?.abort();return;}
  if(method==='closeAll'){await Promise.all([liveCapture.close(), ...[...slots.keys()].map(close)]);return;}
  const controller=new AbortController();requests.set(id,controller);
  let lastPhase='';
  const report=phase=>{if(!controller.signal.aborted&&phase!==lastPhase){lastPhase=phase;self.postMessage({id,phase});}};
  try {
    let result;
    if(method.startsWith('live.')) result=await liveCapture.call(method.slice(5),args,report);
    else if(method==='list') result=await list();
    else if(method==='import') result=await store(args.file,report);
    else if(method==='close') result=await close(args.id);
    else if(method==='remove') {
      if(liveCapture.owns(args.id))throw new Error('キャプチャを停止してから削除してください');
      await close(args.id);
      await transaction(['captures','files'],'readwrite',tx=>{
        tx.objectStore('captures').delete(args.id);tx.objectStore('files').delete(args.id);
      });
    } else if(method==='query') {
      if(liveCapture.owns(args.id)) {
        try {result=await liveCapture.query(args.id,args.operation,args.payload,controller.signal);}
        catch(error) {
          if(controller.signal.aborted||liveCapture.owns(args.id))throw error;
          // Stop may finish while a detail request is in flight. The committed file remains usable.
          const payload={...args.payload};delete payload.after;delete payload.through;
          result=await query(args.id,args.operation,payload,controller.signal,report);
        }
      } else result=await query(args.id,args.operation,args.payload,controller.signal,report);
    }
    else throw new Error('未対応の操作です');
    if(!controller.signal.aborted)self.postMessage({id,result});
  } catch(error) {
    if(!controller.signal.aborted)self.postMessage({id,error:{name:error.name,message:error.message,status:error.status,capturePending:error.capturePending}});
  } finally {requests.delete(id);}
};
