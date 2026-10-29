/* Capture lifecycle is part of the existing file viewer, not a separate workspace. */
(() => {
  'use strict';
  const A=window.PacketApp, {$}=A, dialog=$('live-dialog');
  let active=false,busy=false,timer=null,config=null,opener=null,record=null;
  let polling=false,closed=false,refreshTimer=null,refreshing=false,catalogRequest=0;
  function message(text,error=false) {
    $('live-status').textContent=text;
    $('live-status').classList.toggle('is-error',error);
    $('live-status').setAttribute('role',error?'alert':'status');
  }
  function controls() {
    $('live-options').disabled=active||busy||!config?.interfaces.length;
    $('live-start').hidden=active;
    $('live-start').disabled=busy||!config?.interfaces.length||!$('live-interface').value;
    $('live-save').hidden=!active; $('live-save').disabled=busy;
    $('live-discard').hidden=!active; $('live-discard').disabled=busy;
    $('live-reload').hidden=active; $('live-reload').disabled=busy;
    $('stop-live').hidden=!active; $('stop-live').disabled=busy;
    $('open-live').classList.toggle('is-recording',active);
    $('open-live').textContent=active?'キャプチャ中':'キャプチャ';
    $('open-live').setAttribute('aria-expanded',String(dialog.open));
  }
  function scheduleCatalog() {
    clearTimeout(refreshTimer);
    if(dialog.open&&!active&&!busy&&!closed)refreshTimer=setTimeout(()=>configure(true),4000);
  }
  async function configure(background=false) {
    if(active||busy||refreshing)return;
    const request=++catalogRequest;refreshing=true;
    if(!background){
      busy=true;controls();dialog.classList.add('is-config-loading');
      $('live-config-skeleton').hidden=false;message('ネットワークを確認中…');
    }
    try {
      const result=await A.local.live('config');
      if(request!==catalogRequest||active)return;
      config=result;
      const select=$('live-interface'),previous=select.value,catalog=JSON.stringify(config.interfaces);
      if(select.dataset.catalog!==catalog){
        select.replaceChildren(new Option('選択してください',''));
        for(const item of config.interfaces)select.add(new Option(item.label,item.name));
        select.value=config.interfaces.some(item=>item.name===previous)?previous:'';
        select.dataset.catalog=catalog;
      }
      if(!config.enabled)message(config.reason,true);
      else if(previous&&!select.value)message('選択したネットワークが見つかりません。選び直してください',true);
      else if(!background)message('');
    }catch(error){if(request===catalogRequest){config=null;message(error.message,true);}}
    finally{
      refreshing=false;
      if(!background){busy=false;dialog.classList.remove('is-config-loading');$('live-config-skeleton').hidden=true;}
      controls();scheduleCatalog();
    }
  }
  function show() {
    if(!dialog.open){opener=document.activeElement;dialog.showModal();}
    controls();if(!active&&!busy)void configure();
  }
  function schedule(){clearTimeout(timer);if(active&&!busy&&!closed)timer=setTimeout(poll,500);}
  async function poll() {
    if(!active||busy||polling)return;
    polling=true;
    try {
      const state=await A.local.live('sync');
      if(busy||!active)return;
      record=state.record;A.viewer.updateSource(record);
      if(state.finished){polling=false;await finish();return;}
      await A.viewer.refreshLive(record);
      if(state.state==='failed')message(state.error,true);
      else message(`取得中 · ${state.interface} · ${A.formatSize(record.size)}`);
    }catch(error){message(error.message,true);A.status('キャプチャの更新を再試行しています','error');}
    finally{polling=false;schedule();}
  }
  const number=id=>$(id).value?Number($(id).value):null;
  function readOptions() {
    return {interface:$('live-interface').value,protocol:$('live-protocol').value,host:$('live-host').value.trim(),
      direction:$('live-direction').value,port:$('live-port').value?Number($('live-port').value):null,
      duration:number('live-duration'),size_mib:number('live-size'),
      packets:number('live-packets'),snaplen:number('live-snaplen'),bpf:$('live-bpf').value.trim()};
  }
  async function start(event) {
    event.preventDefault();if(active||busy||!$('live-form').reportValidity())return;
    clearTimeout(refreshTimer);catalogRequest++;
    busy=true;controls();message('キャプチャを開始中…');
    try {
      const state=await A.local.live('start',readOptions());
      active=true;record=state.record;
      if(dialog.open)dialog.close();
      A.status('キャプチャ中');
    }catch(error){
      active=error.capturePending===true;
      message(error.message,true);A.status(error.message,'error');
    }finally{busy=false;controls();schedule();}
  }
  async function finish() {
    if(!active||busy)return;
    clearTimeout(timer);busy=true;controls();message('取得を停止中…');
    try {
      const result=await A.local.live('save');
      active=false;record=result.record;
      A.viewer.updateSource(record);
      await A.viewer.refreshLive(record,true);
      if(dialog.open)dialog.close();
      message(result.error||'保存しました',Boolean(result.error));
      A.status(result.error||'キャプチャを停止しました',result.error?'error':'');
    }catch(error){message(error.message,true);A.status('保存できませんでした。停止ボタンから再試行してください','error');}
    finally{busy=false;controls();}
  }
  async function discard() {
    if(!active||busy||!confirm('このキャプチャファイルを破棄しますか？'))return;
    clearTimeout(timer);busy=true;controls();
    try {
      const result=await A.local.live('discard');active=false;
      if(A.state.active?.id===result.id)A.viewer.resetPacketView();
      localStorage.removeItem(A.storage.pinsPrefix+result.id);localStorage.removeItem(A.storage.viewPrefix+result.id);
      await A.viewer.loadCaptures();message('取得データを破棄しました');
    }catch(error){message(error.message,true);}
    finally{busy=false;controls();}
  }
  A.local.subscribe(event=>{
    if(event.event!=='live')return;
    if(event.type==='created') {
      record=event.record;active=true;
      if(dialog.open)dialog.close();controls();
      A.viewer.updateSource(record);
      void A.viewer.openCapture(record);
      $('packet-scroll').focus({preventScroll:true});
    }
    if(event.type==='failed') {A.viewer.updateSource(event.record);A.status(event.message,'error');}
  });
  $('open-live').addEventListener('click',show);
  $('live-close').addEventListener('click',()=>dialog.close());
  dialog.addEventListener('keydown',event=>{if(event.key==='Escape')event.stopPropagation();});
  dialog.addEventListener('close',()=>{clearTimeout(refreshTimer);controls();opener?.focus({preventScroll:true});});
  $('live-form').addEventListener('submit',start);
  $('live-reload').addEventListener('click',()=>configure());
  $('live-interface').addEventListener('change',controls);
  $('live-save').addEventListener('click',finish);
  $('stop-live').addEventListener('click',finish);
  $('live-discard').addEventListener('click',discard);
  window.addEventListener('pagehide',()=>{closed=true;clearTimeout(timer);clearTimeout(refreshTimer);});
  window.addEventListener('beforeunload',event=>{if(active){event.preventDefault();event.returnValue='';}});
  A.live={isActive:id=>active&&record?.id===id};
  controls();
})();
