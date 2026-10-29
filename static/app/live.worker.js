/* A capture has one browser file from the first click; append commits precede UI updates. */
'use strict';
self.createLiveCapture = ({remote, random, cleanup, create, append, mark, remove, notify}) => {
  const catalogToken = random(32);
  let slot = null;
  const headers = item => ({Authorization: 'Bearer ' + item.token});
  const base = item => '/api/live/sessions/' + item.id;
  const empty = () => ({packets:[],total:0,matched:0,displayed:0,filtered:false,context:0});
  async function request(url, options = {}, binary = false) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), binary ? 120000 : 20000);
    try {
      if (!binary) return await remote(url, {...options, signal:options.signal || controller.signal});
      const response = await fetch(url, {credentials:'omit',cache:'no-store',...options,signal:controller.signal});
      if (!response.ok) {
        const body = await response.json();
        const error = new Error(body.detail || '取得データを受信できません'); error.status=response.status; throw error;
      }
      return {blob:await response.blob(),offset:Number(response.headers.get('X-Capture-Offset')),
        end:Number(response.headers.get('X-Capture-End')),available:Number(response.headers.get('X-Capture-Available'))};
    } finally {clearTimeout(timer);}
  }
  async function start(options) {
    if (slot) throw new Error('現在のキャプチャを停止してください');
    const current = {token:random(32),id:null,record:null,options,offset:0,syncing:null,starting:null};
    slot=current;
    current.starting=(async()=>{
      current.record=await create(options.interface);
      notify({type:'created',record:current.record});
      const state=await request('/api/live/sessions',{method:'POST',headers:{...headers(current),'Content-Type':'application/json'},body:JSON.stringify(options)});
      current.id=state.id;
      return {...state,record:current.record};
    })();
    try {return await current.starting;}
    catch(error) {
      if(current.record) {current.record=await mark(current.record.id,'failed');notify({type:'failed',record:current.record,message:error.message});}
      // A rejected request cannot have started dumpcap; a lost response may have.
      if(error.status>=400 && error.status<500) slot=null;
      throw error;
    }
  }
  async function ensure(current) {
    if(current.id)return;
    // An uncertain POST is recovered with the same capability (idempotent server).
    await current.starting.catch(()=>{});
    const result=await request('/api/live/sessions',{method:'POST',headers:{...headers(current),'Content-Type':'application/json'},body:JSON.stringify(current.options)});
    current.id=result.id;
  }
  async function sync() {
    const current=slot;
    if(!current)throw new Error('取得セッションがありません');
    if(current.syncing)return current.syncing;
    current.syncing=(async()=>{
      await ensure(current);
      let transfer;
      do {
        transfer=await request(base(current)+'/data?offset='+current.offset,{headers:headers(current)},true);
        if(transfer.offset!==current.offset || transfer.end!==current.offset+transfer.blob.size)throw new Error('受信したデータの位置が一致しません');
        if(transfer.blob.size) {
          current.record=await append(current.record.id,transfer.blob,current.offset);
          current.offset=transfer.end;
        }
      } while(transfer.end<transfer.available);
      const state=await request(base(current),{headers:headers(current)});
      // Stop can flush another block between the last read and this status.
      const finished=['complete','failed'].includes(state.state) && current.offset>=state.bytes;
      return {...state,record:current.record,finished};
    })();
    try{return await current.syncing;}finally{current.syncing=null;}
  }
  async function finalize() {
    const current=slot;
    if(!current)throw new Error('取得セッションがありません');
    await ensure(current);
    if(current.syncing)await current.syncing;
    await request(base(current)+'/stop',{method:'POST',headers:headers(current)});
    const state=await sync();
    if(!state.finished)throw new Error('取得データの保存が完了していません。停止を再試行してください');
    current.record=await mark(current.record.id,state.state==='failed'?'failed':'complete');
    await cleanup(base(current),current);
    if(slot===current)slot=null;
    return {record:current.record,state:state.state,error:state.error};
  }
  async function discard() {
    const current=slot;if(!current)return;
    await ensure(current);
    if(current.syncing)await current.syncing;
    await request(base(current)+'/stop',{method:'POST',headers:headers(current)});
    if(current.syncing)await current.syncing.catch(()=>{});
    await remove(current.record.id);
    await cleanup(base(current),current);
    if(slot===current)slot=null;
    return {id:current.record.id};
  }
  return {
    owns:id=>slot?.record?.id===id,
    query:async(id,operation,payload,signal)=>{
      const current=slot;
      if(!current || current.record?.id!==id)throw new Error('取得ファイルが見つかりません');
      if(!current.id || !current.offset) {
        if(operation==='packets')return empty();
        throw new Error('パケットを受信していません');
      }
      return remote(base(current)+'/query',{method:'POST',headers:{...headers(current),'Content-Type':'application/json'},
        body:JSON.stringify({operation,payload:{...payload,through:current.offset}}),signal});
    },
    close:async()=>{
      const current=slot;if(!current)return;
      // Keep the committed prefix when the page is closed, never discard the file.
      if(current.record)await mark(current.record.id,'interrupted').catch(()=>{});
      if(current.id)await cleanup(base(current),current);
    },
    call:async(method,args)=>{
      if(method==='config')return request('/api/live/config',{headers:{Authorization:'Bearer '+catalogToken}});
      if(method==='start')return start(args);
      if(method==='sync')return sync();
      if(method==='save')return finalize();
      if(method==='discard')return discard();
      throw new Error('未対応のキャプチャ操作です');
    },
  };
};
