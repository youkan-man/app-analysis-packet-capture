/* UI-to-worker boundary. The UI receives data, never server instance credentials. */
(() => {
  'use strict';
  const A=window.PacketApp, pending=new Map();
  const worker=new Worker('/static/app/storage.worker.js');
  let sequence=0, fatal=null;
  worker.onmessage=({data})=>{
    const request=pending.get(data.id);if(!request)return;
    if (data.phase) {request.onProgress?.(data.phase); return;}
    pending.delete(data.id);request.cleanup();
    if(data.error){const error=new Error(data.error.message);error.name=data.error.name;error.status=data.error.status;request.reject(error);}
    else request.resolve(data.result);
  };
  worker.onerror=worker.onmessageerror=()=>{
    fatal=new Error('バックグラウンド処理を開始できません。再読み込みしてください');
    for(const request of pending.values()){request.cleanup();request.reject(fatal);}
    pending.clear();
  };
  function call(method,args={},signal,onProgress) {
    return new Promise((resolve,reject)=>{
      if(fatal){reject(fatal);return;}
      if(signal?.aborted){reject(new DOMException('処理を中止しました','AbortError'));return;}
      const id=++sequence;
      const abort=()=>{
        pending.delete(id);worker.postMessage({id,method:'cancel'});
        reject(new DOMException('処理を中止しました','AbortError'));
      };
      const cleanup=()=>signal?.removeEventListener('abort',abort);
      pending.set(id,{resolve,reject,cleanup,onProgress});
      signal?.addEventListener('abort',abort,{once:true});
      try {worker.postMessage({id,method,args});}
      catch(error){pending.delete(id);cleanup();reject(error);}
    });
  }
  window.addEventListener('pagehide',()=>worker.postMessage({method:'closeAll'}));
  A.local={
    live:(method,args={},onProgress)=>call("live."+method,args,undefined,onProgress),
    list:()=>call('list'),import:(file,onProgress)=>call('import',{file},undefined,onProgress),remove:id=>call('remove',{id}),
    close:id=>call('close',{id}),query:(id,operation,payload={},signal,onProgress)=>call('query',{id,operation,payload},signal,onProgress),
  };
})();
