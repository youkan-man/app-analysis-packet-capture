/* Capture source lifecycle and continuous packet-query orchestration. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, el, button, status, formatSize, api, storage, parseStored,
    defaultView, normalizeView, normalizePins, hasFilters, filterCount } = A;
  A.viewer = A.viewer || {};

  function renderSources() {
    $("capture-count").textContent = String(state.captures.length);
    const container = $("capture-list"); container.replaceChildren();
    for (const capture of state.captures) {
      const row = el("div", "capture-item" + (capture.id === state.active?.id ? " active" : ""));
      row.dataset.captureId = capture.id;
      const open = button("", () => openCapture(capture), "capture-open");
      open.append(el("strong", "", capture.filename), el("span", "", capture.format.toUpperCase() + " · " + formatSize(capture.size)));
      open.title = capture.filename;
      row.classList.toggle('is-capturing', A.live?.isActive(capture.id) || capture.phase === 'recording');
      const remove = button("×", async event => {
        event.stopPropagation();
        if (!confirm("このブラウザのローカルファイルを削除しますか？\n" + capture.filename)) return;
        try {
          await A.local.remove(capture.id);
          localStorage.removeItem(storage.viewPrefix + capture.id);
          localStorage.removeItem(storage.pinsPrefix + capture.id);
          if (capture.id === state.active?.id) resetPacketView();
          await loadCaptures();
        } catch (error) { status(error.message, "error"); }
      }, "remove-capture");
      remove.setAttribute("aria-label", capture.filename + " を削除");
      row.append(open, remove); container.append(row);
    }
    if (!state.captures.length) container.append(el("div", "empty-detail", "ファイルはありません"));
  }
  function updateSource(record) {
    const index=state.captures.findIndex(item=>item.id===record.id);
    if(index<0){state.captures.unshift(record);renderSources();}
    else {
      Object.assign(state.captures[index],record);
      const row=$('capture-list').querySelector(`[data-capture-id="${record.id}"]`);
      if(row){
        row.classList.toggle('is-capturing',record.phase==='recording');
        row.querySelector('.capture-open span').textContent=record.format.toUpperCase()+' · '+formatSize(record.size)+
          (record.phase==='recording'?' · 取得中':record.phase==='failed'?' · 取得終了':'');
      }
    }
    if(state.active?.id===record.id){Object.assign(state.active,record);$('source-info').textContent=record.format.toUpperCase()+' · '+formatSize(record.size)+' · ローカル保存';}
  }
  let updating=false;
  async function refreshLive(record,final=false) {
    if(state.active?.id!==record.id)return;
    if(updating || state.listLoading){if(final)await loadPackets({keepSelection:true,background:true});return;}
    updating=true;
    const capture=state.active.id, signature=JSON.stringify(state.view);
    const params={raw:state.view.raw.trim(),view:state.view.groups.length?JSON.stringify({groups:state.view.groups}):'',context:hasFilters()?state.view.context:0};
    if(!final&&!hasFilters())params.after=state.packets.at(-1)?.number||0;
    try {
      const result=await A.local.query(capture,'packets',params);
      if(state.active?.id!==capture||JSON.stringify(state.view)!==signature||state.listLoading)return;
      const scroll=$('packet-scroll'),top=scroll.scrollTop;
      if(result.incremental) {
        const last=state.packets.at(-1)?.number||0;
        state.packets.push(...result.packets.filter(packet=>packet.number>last));
      }else state.packets=result.packets;
      state.total=result.total;state.matched=result.matched;state.displayed=result.displayed;
      for(const packet of result.packets)state.packetCache.set(packet.number,packet);
      A.viewer.renderVirtualRows(true);renderCounts();scroll.scrollTop=top;
      if(!state.selected && state.packets.length)void A.viewer.selectPacket(state.packets[0].number,{scroll:false});
    }finally{updating=false;}
  }
  function resetPacketView() {
    A.loading.clear("packets", "detail");
    state.listController?.abort(); state.detailController?.abort(); A.relations?.close();
    if (state.active) A.local.close(state.active.id);
    $("close-capture").disabled = true;
    state.active = null; state.packets = []; state.packetCache.clear();
    state.total = state.matched = state.displayed = 0;
    state.selected = null; state.selectedDetail = null; state.pins = []; state.view = defaultView();
    localStorage.removeItem(storage.current);
    $("current-file").textContent = "キャプチャを選択";
    $("source-info").textContent = "ファイルを選択してください";
    renderAll(); A.viewer.clearDetail(); A.pins.closeCompare(); renderSources();
  }
  async function loadCaptures() {
    const loading = A.loading.begin("library", "ローカルファイル一覧を読み込み中…");
    try {
      const result = await A.local.list(); state.captures = result.items;
      loading.end();
      const current = state.active?.id || localStorage.getItem(storage.current);
      const capture = state.captures.find(item => item.id === current) || state.captures[0];
      if (capture && capture.id !== state.active?.id) await openCapture(capture);
      if (!capture) resetPacketView();
      renderSources();
    } catch (error) { loading.fail(error.message); status("ファイル一覧: " + error.message, "error"); }
    finally { loading.end(); }
  }
  async function openCapture(capture) {
    A.loading.clear("detail");
    state.listController?.abort(); state.detailController?.abort(); A.relations?.close();
    if (state.active && state.active.id !== capture.id) A.local.close(state.active.id);
    $("close-capture").disabled = false;
    state.packets = []; state.active = capture; state.selected = null; state.selectedDetail = null;
    state.packetCache.clear(); state.compareDetails.clear();
    localStorage.setItem(storage.current, capture.id);
    state.view = normalizeView(parseStored(storage.viewPrefix + capture.id, defaultView()));
    state.pins = normalizePins(parseStored(storage.pinsPrefix + capture.id, []));
    $("current-file").textContent = capture.filename;
    $("source-info").textContent = capture.format.toUpperCase() + " · " + formatSize(capture.size) + " · ローカル保存";
    renderSources(); A.filters.renderFilterDrawer(); A.pins.renderPins();
    A.viewer.clearDetail(); A.pins.closeCompare(); await loadPackets();
  }
  async function loadPackets(options = {}) {
    if (!state.active) { renderAll(); return; }
    state.listController?.abort(); if(!options.background)state.detailController?.abort();
    const controller = new AbortController(); state.listController = controller;
    const captureId = state.active.id;
    state.listLoading=true;
    if(!options.background)A.loading.clear("detail");
    const quiet={progress:()=>{},end:()=>{},fail:()=>{}};
    const loading = options.background ? quiet : A.loading.begin("packets", hasFilters() ? "フィルターを適用中…" : "パケットを解析中…", state.active.filename);
    status("パケットを解析中...", "busy");
    try {
      const result = await A.local.query(captureId, 'packets', {
        raw: state.view.raw.trim(), view: state.view.groups.length ? JSON.stringify({groups: state.view.groups}) : '',
        context: hasFilters() ? state.view.context : 0,
      }, controller.signal, loading.progress);
      if (controller !== state.listController || state.active?.id !== captureId) return;
      state.packets = result.packets; state.total = result.total; state.matched = result.matched; state.displayed = result.displayed;
      for (const packet of state.packets) state.packetCache.set(packet.number, packet);
      const keep = options.keepSelection && state.packets.some(packet => packet.number === state.selected);
      if (!keep) state.selected = state.packets.find(packet => packet.is_match)?.number ?? state.packets[0]?.number ?? null;
      if(!options.background)$("packet-scroll").scrollTop = 0;
      renderAll();
      loading.end();
      if (state.selected && (!options.background || !state.selectedDetail)) await A.viewer.selectPacket(state.selected, { scroll: false }); else if(!state.selected)A.viewer.clearDetail();
      if (controller !== state.listController || controller.signal.aborted) return;
      const contextText = result.displayed > result.matched ? `（前後 ${result.displayed - result.matched}件を透過）` : "";
      status(result.filtered ? `${result.matched}件に一致 ${contextText}` : `${result.total}件を表示`);
    } catch (error) {
      if (controller.signal.aborted) return;
      state.packets = []; state.total = state.matched = state.displayed = 0; state.selected = null;
      renderAll(); A.viewer.clearDetail();
      loading.fail(error.message);
      status("フィルター/解析: " + error.message, "error"); $("filter-error").textContent = error.message;
    } finally { loading.end(); if(controller===state.listController)state.listLoading=false; }
  }
  function renderAll() {
    A.filters.renderActiveFilters(); A.pins.renderPins(); A.viewer.renderVirtualRows(true); renderCounts();
  }
  function renderCounts() {
    $("packet-count").textContent = String(state.total);
    const filtered = hasFilters();
    $("packet-status").textContent = filtered ? `一致 ${state.matched} / 全 ${state.total}` : `${state.total}件・連続表示`;
    $("status-total").textContent = filtered ? `表示 ${state.displayed} / 一致 ${state.matched} / 全 ${state.total}` : `表示 ${state.displayed} / ${state.total}`;
    $("filter-count").textContent = String(filterCount());
    $("toggle-filter").classList.toggle("button-primary", filterCount() > 0);
  }
  Object.assign(A.viewer, {renderSources, resetPacketView, loadCaptures, openCapture, loadPackets, renderAll, renderCounts, updateSource, refreshLive});
})();
