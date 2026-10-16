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
      : 'ブラウザへの保存に失敗しました。ファイルは送信していません'));
    tx.onerror = () => {}; // onabort is the single failure boundary.
  });
}
async function list() {
  const items = await transaction(['captures'],'readonly',tx=>tx.objectStore('captures').getAll());
  return {items:items.sort((a,b)=>b.added.localeCompare(a.added))};
}
async function store(file) {
  if (!(file instanceof Blob)) throw new Error('ファイルがありません');
  const magic = Array.from(new Uint8Array(await file.slice(0,4).arrayBuffer()),n=>n.toString(16).padStart(2,'0')).join('');
  const formats = {d4c3b2a1:'pcap',a1b2c3d4:'pcap','4d3cb2a1':'pcap',a1b23c4d:'pcap','0a0d0d0a':'pcapng'};
  if (!formats[magic]) throw new Error('PCAP / PCAPNG ファイルではありません');
  const record = {id:random(16),filename:(file.name || 'capture.pcap').replaceAll('\\','/').split('/').pop(),
    size:file.size,format:formats[magic],added:new Date().toISOString()};
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
function instance(localId) {
  let slot=slots.get(localId);
  if (slot) return slot;
  slot={token:random(32),controller:new AbortController(),id:null,closed:false};
  slots.set(localId,slot);
  slot.ready=(async()=>{
    const file=await transaction(['files'],'readonly',tx=>tx.objectStore('files').get(localId));
    if (!file) throw new Error('ローカルファイルが見つかりません。もう一度開いてください');
    if (slot.closed) throw aborted();
    const result=await remote('/api/instances',{method:'POST',headers:{...authorize(slot),'Content-Type':'application/octet-stream'},
      body:file,signal:slot.controller.signal});
    slot.id=result.id;
    if (slot.closed) {await release(slot); throw aborted();}
    return slot;
  })().catch(error=>{if(slots.get(localId)===slot)slots.delete(localId);throw error;});
  return slot;
}
async function release(slot) {
  if (!slot.id) return;
  await remote('/api/instances/'+slot.id,{method:'DELETE',headers:authorize(slot),keepalive:true}).catch(()=>{});
}
async function close(localId) {
  const slot=slots.get(localId); if(!slot)return;
  slots.delete(localId);slot.closed=true;slot.controller.abort();
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
async function query(localId,operation,payload,signal) {
  for(let attempt=0;attempt<2;attempt++) {
    if(signal.aborted)throw aborted();
    const slot=instance(localId);
    let jobURL;
    try {
      await slot.ready;
      if(signal.aborted||slot.closed)throw aborted();
      const base='/api/instances/'+slot.id;
      const job=await remote(base+'/jobs',{method:'POST',headers:{...authorize(slot),'Content-Type':'application/json'},
        body:JSON.stringify({operation,payload}),signal});
      jobURL=base+'/jobs/'+job.id;
      let delay=80;
      while(true) {
        const state=await remote(jobURL,{headers:authorize(slot),signal});
        if(state.state==='done')return state.result;
        if(state.state==='error')throw new Error(state.error);
        await pause(delay,signal);delay=Math.min(500,delay*1.3);
      }
    } catch(error) {
      if(error.status===404&&attempt===0&&!signal.aborted&&!slot.closed&&slots.get(localId)===slot) {
        // A restart or idle expiry never loses the browser's source file.
        await close(localId);continue;
      }
      throw error;
    } finally {
      if(jobURL)await remote(jobURL,{method:'DELETE',headers:authorize(slot),keepalive:true}).catch(()=>{});
    }
  }
  throw new Error('解析インスタンスを開き直せませんでした');
}
self.onmessage=async event=>{
  const {id,method,args}=event.data;
  if(method==='cancel'){requests.get(id)?.abort();return;}
  if(method==='closeAll'){await Promise.all([...slots.keys()].map(close));return;}
  const controller=new AbortController();requests.set(id,controller);
  try {
    let result;
    if(method==='list') result=await list();
    else if(method==='import') result=await store(args.file);
    else if(method==='close') result=await close(args.id);
    else if(method==='remove') {
      await close(args.id);
      await transaction(['captures','files'],'readwrite',tx=>{
        tx.objectStore('captures').delete(args.id);tx.objectStore('files').delete(args.id);
      });
    } else if(method==='query') result=await query(args.id,args.operation,args.payload,controller.signal);
    else throw new Error('未対応の操作です');
    if(!controller.signal.aborted)self.postMessage({id,result});
  } catch(error) {
    if(!controller.signal.aborted)self.postMessage({id,error:{name:error.name,message:error.message}});
  } finally {requests.delete(id);}
};
