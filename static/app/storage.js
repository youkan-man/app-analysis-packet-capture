/* UI-to-worker boundary. The UI receives data, never server instance credentials. */
(() => {
  'use strict';
  const A=window.PacketApp, pending=new Map();
  const worker=new Worker('/static/app/storage.worker.js');
  let sequence=0;
  worker.onmessage=({data})=>{
    const request=pending.get(data.id);if(!request)return;
    pending.delete(data.id);request.cleanup();
    if(data.error){const error=new Error(data.error.message);error.name=data.error.name;request.reject(error);}
    else request.resolve(data.result);
  };
  worker.onerror=()=>{
    for(const request of pending.values()){request.cleanup();request.reject(new Error('バックグラウンド処理を開始できません。再読み込みしてください'));}
    pending.clear();
  };
  function call(method,args={},signal) {
    return new Promise((resolve,reject)=>{
      if(signal?.aborted){reject(new DOMException('処理を中止しました','AbortError'));return;}
      const id=++sequence;
      const abort=()=>{
        pending.delete(id);worker.postMessage({id,method:'cancel'});
        reject(new DOMException('処理を中止しました','AbortError'));
      };
      const cleanup=()=>signal?.removeEventListener('abort',abort);
      pending.set(id,{resolve,reject,cleanup});
      signal?.addEventListener('abort',abort,{once:true});
      worker.postMessage({id,method,args});
    });
  }
  window.addEventListener('pagehide',()=>worker.postMessage({method:'closeAll'}));
  A.local={
    list:()=>call('list'),import:file=>call('import',{file}),remove:id=>call('remove',{id}),
    close:id=>call('close',{id}),query:(id,operation,payload={},signal)=>call('query',{id,operation,payload},signal),
  };
})();
