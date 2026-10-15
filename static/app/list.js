/* Virtualized packet rows and selected-record navigation. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, el, button, api, OVERSCAN, hasFilters } = A;
  A.viewer = A.viewer || {};

  function renderVirtualRows(force = false) {
    const scroll = $("packet-scroll"), body = $("packet-rows"), empty = $("packet-empty");
    empty.hidden = state.packets.length > 0;
    empty.textContent = state.active
      ? (hasFilters() ? "一致するパケットはありません。" : "パケットがありません。")
      : "PCAP / PCAPNG を開くとパケットが表示されます。";
    if (!state.packets.length) { body.replaceChildren(); return; }
    const ROW_HEIGHT = A.layout?.rowHeight() || 24;
    const height = scroll.clientHeight || 300;
    const start = Math.max(0, Math.floor(scroll.scrollTop / ROW_HEIGHT) - OVERSCAN);
    const end = Math.min(state.packets.length, Math.ceil((scroll.scrollTop + height) / ROW_HEIGHT) + OVERSCAN);
    if (!force && body.dataset.range === `${start}:${end}`) return;
    body.dataset.range = `${start}:${end}`;
    const fragment = document.createDocumentFragment();
    if (start) fragment.append(spacer(start * ROW_HEIGHT));
    for (let index = start; index < end; index++) fragment.append(packetRow(state.packets[index]));
    if (end < state.packets.length) fragment.append(spacer((state.packets.length - end) * ROW_HEIGHT));
    body.replaceChildren(fragment);
  }
  function spacer(height) {
    const row = el("tr", "virtual-spacer"), cell = el("td");
    cell.colSpan = 8;
    cell.style.height = `${height}px`;
    row.append(cell);
    return row;
  }
  function packetRow(packet) {
    const proto = String(packet.protocol || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const classes = [`proto-${proto}`];
    if (!packet.is_match) classes.push("context-row");
    if (A.pins.isPinned(packet.number)) classes.push("pinned");
    if (packet.number === state.selected) classes.push("selected");
    const row = el("tr", classes.join(" "));
    row.dataset.number = String(packet.number);
    row.tabIndex = 0;
    row.setAttribute("aria-selected", String(packet.number === state.selected));
    const pinCell = el("td"), pinned = A.pins.isPinned(packet.number);
    const pin = button(pinned ? "◆" : "◇", event => {
      event.stopPropagation(); A.pins.togglePin(packet);
    }, "pin-button" + (pinned ? " active" : ""));
    pin.setAttribute("aria-label", pinned ? "ピンを解除" : "ピン留め");
    pinCell.append(pin); row.append(pinCell);
    for (const field of Object.keys(A.columns)) row.append(valueCell(packet, field));
    row.addEventListener("click", event => {
      if (!event.target.closest("button") && window.getSelection()?.isCollapsed !== false) selectPacket(packet.number);
    });
    // Keep normal drag-to-select text, but reserve a second mouse press for pinning.
    // Buttons keep their existing actions and must not also pin the parent record.
    const isControl = event => event.target.closest("button, a, input, select, textarea, [role=button]");
    row.addEventListener("mousedown", event => {
      if (event.button === 0 && event.detail > 1 && !isControl(event)) event.preventDefault();
    });
    row.addEventListener("dblclick", event => {
      if (event.button !== 0 || isControl(event)) return;
      event.preventDefault();
      // Double-click is idempotent pinning; removal stays on the explicit controls.
      if (!A.pins.isPinned(packet.number)) A.pins.togglePin(packet);
    });
    row.addEventListener("contextmenu", event => {
      const cell = event.target.closest("td[data-field]");
      event.preventDefault();
      A.filters.showPacketMenu(packet, cell?.dataset.field || "info", cell || row, event.clientX, event.clientY);
    });
    row.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault(); selectPacket(packet.number);
      }
      if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
        event.preventDefault();
        const cell = row.querySelector('td[data-field="info"]'), rect = cell.getBoundingClientRect();
        A.filters.showPacketMenu(packet, "info", cell, rect.left + 18, rect.top + 15);
      }
    });
    return row;
  }
  function valueCell(packet, field) {
    const cell = el("td", "value-cell");
    cell.dataset.field = field; cell.dataset.scope = "column";
    const value = String(packet[field] ?? ""), span = el("span", "value-text", value);
    cell.append(span); cell.title = value;
    return cell;
  }
  async function selectPacket(number, options = {}) {
    if (!state.active || !number) return;
    state.selected = number;
    document.querySelectorAll('#packet-rows tr[data-number]').forEach(row => {
      row.classList.toggle('selected', Number(row.dataset.number) === number);
      row.setAttribute('aria-selected', String(Number(row.dataset.number) === number));
    });
    if (options.scroll !== false) scrollToPacket(number);
    state.detailController?.abort();
    const controller = new AbortController(); state.detailController = controller;
    const captureId = state.active.id;
    A.viewer.clearDetail();
    $("selected-number").textContent = "#" + number;
    $("packet-details").replaceChildren(el("div", "empty-detail", "解析中..."));
    try {
      const detail = await api(`/api/captures/${captureId}/packets/${number}`, { signal: controller.signal });
      if (controller !== state.detailController || state.active?.id !== captureId) return;
      state.selectedDetail = detail; state.compareDetails.set(number, detail);
      A.viewer.renderDetails(detail.layers); A.viewer.renderHex(detail.hex); A.pins.renderPins();
    } catch (error) {
      if (!controller.signal.aborted) $("packet-details").replaceChildren(el("div", "empty-detail", error.message));
    }
  }
  function scrollToPacket(number) {
    const index = state.packets.findIndex(packet => packet.number === number);
    if (index < 0) return;
    const scroll = $("packet-scroll"), height = A.layout?.rowHeight() || 24;
    const top = index * height;
    if (top < scroll.scrollTop || top + height > scroll.scrollTop + scroll.clientHeight) {
      scroll.scrollTop = Math.max(0, top - scroll.clientHeight / 2);
    }
  }
  Object.assign(A.viewer, { renderVirtualRows, selectPacket });
})();
