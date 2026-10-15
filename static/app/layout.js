/* Persistent pane/column geometry and accessible resize handles. */
(() => {
  'use strict';
  const A = window.PacketApp, {$, el} = A;
  const key = 'packetcap.layout.v3';
  const defaults = {source:170,right:380,relations:430,packets:60,detail:50,compare:58,
    font:12,widths:[32,52,110,134,134,85,64,260]};
  let stored = A.parseStored(key,{});
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) stored = {};
  const prefs = {...defaults, widths:[...defaults.widths]};
  Object.keys(defaults).filter(name=>name!=='widths').forEach(name=>{if(Number.isFinite(stored[name])) prefs[name]=stored[name];});
  if(Array.isArray(stored.widths) && stored.widths.length===8 && stored.widths.every(Number.isFinite)) prefs.widths=[...stored.widths];
  const clamp=(x,lo,hi)=>Math.max(lo,Math.min(hi,x));
  const mobile=()=>window.innerWidth<=720;
  const save=()=>{try{localStorage.setItem(key,JSON.stringify(prefs));}catch{}};
  const setters=[];
  function separator(id,label,axis,read,write,extent,limits,reset,parent,after) {
    const node=el('div','splitter');node.id=id;node.tabIndex=0;
    node.setAttribute('role','separator');node.setAttribute('aria-label',label);
    function update() {
      const [lo,hi]=limits();node.dataset.axis=axis();
      node.setAttribute('aria-orientation',axis()==='x'?'vertical':'horizontal');
      node.setAttribute('aria-valuemin',String(lo));node.setAttribute('aria-valuemax',String(hi));
      node.setAttribute('aria-valuenow',String(Math.round(read())));
    }
    function set(value) {const [lo,hi]=limits();write(clamp(value,lo,hi));refresh();update();}
    let drag=null;
    node.addEventListener('pointerdown',event=>{
      if(event.button!==0)return;
      event.preventDefault();node.focus();node.setPointerCapture(event.pointerId);
      drag={start:axis()==='x'?event.clientX:event.clientY,value:read(),scale:extent()};
      document.body.classList.add('pane-resizing');A.filters.hideSelectionTools();
    });
    node.addEventListener('pointermove',event=>{
      if(!drag)return;
      set(drag.value+((axis()==='x'?event.clientX:event.clientY)-drag.start)*drag.scale);
    });
    function stop(event){if(!drag)return;drag=null;document.body.classList.remove('pane-resizing');save();
      if(node.hasPointerCapture(event.pointerId))node.releasePointerCapture(event.pointerId);}
    node.addEventListener('pointerup',stop);node.addEventListener('pointercancel',stop);
    node.addEventListener('lostpointercapture',()=>{drag=null;document.body.classList.remove('pane-resizing');});
    node.addEventListener('keydown',event=>{
      const keys=axis()==='x'?['ArrowLeft','ArrowRight']:['ArrowUp','ArrowDown'];
      if(event.key==='Home'){event.preventDefault();set(reset);save();}
      if(!keys.includes(event.key))return;
      event.preventDefault();set(read()+(event.key===keys[0]?-1:1)*Math.sign(extent())*(event.shiftKey?10:2));save();
    });
    node.addEventListener('dblclick',()=>{set(reset);save();});
    if(after)after.after(node);else parent.prepend(node);
    setters.push(update);update();return node;
  }
  function refresh() {
    const style=document.documentElement.style;
    prefs.font=clamp(prefs.font,10,16);prefs.packets=clamp(prefs.packets,25,78);prefs.detail=clamp(prefs.detail,20,80);
    style.setProperty('--ui-font-size',prefs.font+'px');style.setProperty('--row-height',(prefs.font+12)+'px');
    style.setProperty('--byte-row-height',(prefs.font+9)+'px');
    style.setProperty('--source-width',clamp(prefs.source,110,360)+'px');
    style.setProperty('--right-width',clamp(prefs.right,280,650)+'px');
    style.setProperty('--relations-width',clamp(prefs.relations,280,650)+'px');
    style.setProperty('--packet-share',prefs.packets+'%');style.setProperty('--detail-share',prefs.detail+'%');
    style.setProperty('--compare-share',clamp(prefs.compare,25,80)+'%');
    const cols=document.querySelectorAll('.packet-table col'),widths=prefs.widths.map((w,i)=>clamp(w,i===0?28:48,900));
    widths[7]=Math.max(widths[7],$('packet-scroll').clientWidth-widths.slice(0,7).reduce((a,b)=>a+b,0));
    cols.forEach((col,i)=>{col.style.width=`${widths[i]}px`;});
    document.querySelector('.packet-table').style.width=widths.reduce((a,b)=>a+b,0)+'px';
    setters.forEach(update=>update());A.viewer.renderVirtualRows(true);
  }
  function init() {
    const workspace=$('workspace'),viewer=document.querySelector('.viewer'),inspect=document.querySelector('.inspect-grid');
    separator('split-sources','ファイルとデータの境界',()=> 'x',()=>prefs.source,v=>prefs.source=v,()=>1,()=>[110,Math.min(360,innerWidth/3)],170,workspace,document.querySelector('.source-panel'));
    separator('split-right','右ペインの境界',()=> 'x',()=>workspace.classList.contains('relations-open')?prefs.relations:prefs.right,
      v=>{if(workspace.classList.contains('relations-open'))prefs.relations=v;else prefs.right=v;},()=>-1,()=>[280,Math.min(650,innerWidth*.6)],380,workspace,viewer);
    separator('split-packets','一覧と詳細の境界',()=> 'y',()=>prefs.packets,v=>prefs.packets=v,()=>100/viewer.clientHeight,()=>[25,78],60,viewer,document.querySelector('.packet-section'));
    separator('split-inspect','詳細とバイトの境界',()=>mobile()?'y':'x',()=>prefs.detail,v=>prefs.detail=v,()=>100/(mobile()?inspect.clientHeight:inspect.clientWidth),()=>[20,80],50,inspect,document.querySelector('.details-panel'));
    separator('split-compare','比較ペインの高さ',()=> 'y',()=>prefs.compare,v=>prefs.compare=v,()=>-100/viewer.clientHeight,()=>[25,80],58,$('compare-panel'),null);
    document.querySelectorAll('.packet-table thead th').forEach((th,i)=>{
      separator(`resize-column-${i}`,`${th.textContent||'ピン'}列の幅`,()=> 'x',()=>prefs.widths[i],v=>prefs.widths[i]=v,()=>1,()=>[i===0?28:48,900],defaults.widths[i],th,null);
    });
    const label=el('label','font-control','文字 ');
    const font=A.select([10,11,12,13,14,16].map(v=>[String(v),String(v)]),String(prefs.font),value=>{prefs.font=Number(value);refresh();save();});
    font.id='font-size';font.setAttribute('aria-label','フォントサイズ');label.append(font);$('refresh').before(label);
    refresh();new ResizeObserver(refresh).observe($('packet-scroll'));window.addEventListener('resize',refresh);
  }
  A.layout={init,refresh,rowHeight:()=>prefs.font+12};
})();
