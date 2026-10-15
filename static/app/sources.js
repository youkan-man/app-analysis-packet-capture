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
      const open = button("", () => openCapture(capture), "capture-open");
      open.append(el("strong", "", capture.filename), el("span", "", capture.format.toUpperCase() + " · " + formatSize(capture.size)));
      open.title = capture.filename;
      const remove = button("×", async event => {
        event.stopPropagation();
        if (!confirm("このキャプチャを削除しますか？\n" + capture.filename)) return;
        try {
          await api("/api/captures/" + encodeURIComponent(capture.id), { method: "DELETE" });
          if (capture.id === state.active?.id) resetPacketView();
          await loadCaptures();
        } catch (error) { status(error.message, "error"); }
      }, "remove-capture");
      remove.setAttribute("aria-label", capture.filename + " を削除");
      row.append(open, remove); container.append(row);
    }
    if (!state.captures.length) container.append(el("div", "empty-detail", "ファイルはありません"));
  }
  function resetPacketView() {
    state.listController?.abort(); state.detailController?.abort(); A.relations?.close();
    state.active = null; state.packets = []; state.packetCache.clear();
    state.total = state.matched = state.displayed = 0;
    state.selected = null; state.selectedDetail = null; state.pins = []; state.view = defaultView();
    localStorage.removeItem(storage.current);
    $("current-file").textContent = "キャプチャを選択";
    $("source-info").textContent = "ファイルを選択してください";
    renderAll(); A.viewer.clearDetail();
  }
  async function loadCaptures() {
    try {
      const result = await api("/api/captures"); state.captures = result.items;
      const current = state.active?.id || localStorage.getItem(storage.current);
      const capture = state.captures.find(item => item.id === current) || state.captures[0];
      if (capture && capture.id !== state.active?.id) await openCapture(capture);
      if (!capture) resetPacketView();
      renderSources();
    } catch (error) { status("ファイル一覧: " + error.message, "error"); }
  }
  async function openCapture(capture) {
    state.listController?.abort(); state.detailController?.abort(); A.relations?.close();
    state.packets = []; state.active = capture; state.selected = null; state.selectedDetail = null;
    state.packetCache.clear(); state.compareDetails.clear();
    localStorage.setItem(storage.current, capture.id);
    state.view = normalizeView(parseStored(storage.viewPrefix + capture.id, defaultView()));
    state.pins = normalizePins(parseStored(storage.pinsPrefix + capture.id, []));
    $("current-file").textContent = capture.filename;
    $("source-info").textContent = capture.format.toUpperCase() + " · " + formatSize(capture.size);
    renderSources(); A.filters.renderFilterDrawer(); A.pins.renderPins();
    A.viewer.clearDetail(); A.pins.closeCompare(); await loadPackets();
  }
  async function loadPackets(options = {}) {
    if (!state.active) { renderAll(); return; }
    state.listController?.abort(); state.detailController?.abort();
    const controller = new AbortController(); state.listController = controller;
    const captureId = state.active.id;
    status("パケットを解析中...", "busy");
    const params = new URLSearchParams();
    if (state.view.raw.trim()) params.set("raw", state.view.raw.trim());
    if (state.view.groups.length) params.set("view", JSON.stringify({ groups: state.view.groups }));
    if (state.view.context && hasFilters()) params.set("context", String(state.view.context));
    try {
      const result = await api(`/api/captures/${encodeURIComponent(captureId)}/packets?${params}`, { signal: controller.signal });
      if (controller !== state.listController || state.active?.id !== captureId) return;
      state.packets = result.packets; state.total = result.total; state.matched = result.matched; state.displayed = result.displayed;
      for (const packet of state.packets) state.packetCache.set(packet.number, packet);
      const keep = options.keepSelection && state.packets.some(packet => packet.number === state.selected);
      if (!keep) state.selected = state.packets.find(packet => packet.is_match)?.number ?? state.packets[0]?.number ?? null;
      $("packet-scroll").scrollTop = 0;
      renderAll();
      if (state.selected) await A.viewer.selectPacket(state.selected, { scroll: false }); else A.viewer.clearDetail();
      if (controller !== state.listController || controller.signal.aborted) return;
      const contextText = result.displayed > result.matched ? `（前後 ${result.displayed - result.matched}件を透過）` : "";
      status(result.filtered ? `${result.matched}件に一致 ${contextText}` : `${result.total}件を表示`);
    } catch (error) {
      if (controller.signal.aborted) return;
      state.packets = []; state.total = state.matched = state.displayed = 0; state.selected = null;
      renderAll(); A.viewer.clearDetail();
      status("フィルター/解析: " + error.message, "error"); $("filter-error").textContent = error.message;
    }
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
  Object.assign(A.viewer, {renderSources, resetPacketView, loadCaptures, openCapture, loadPackets, renderAll, renderCounts});
})();
