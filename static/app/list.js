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
    const existing=new Map([...body.querySelectorAll('tr[data-number]')].filter(row=>row.dataset.capture===state.active?.id).map(row=>[Number(row.dataset.number),row]));
    const desired=[];
    if(start)desired.push(spacer(start*ROW_HEIGHT));
    for(let index=start;index<end;index++) {
      const packet=state.packets[index],row=existing.get(packet.number)||packetRow(packet);
      row.classList.toggle('selected',packet.number===state.selected);
      row.classList.toggle('context-row',!packet.is_match);
      row.classList.toggle('pinned',A.pins.isPinned(packet.number));
      row.setAttribute('aria-selected',String(packet.number===state.selected));
      row.setAttribute('aria-rowindex',String(index+2));
      row.tabIndex=packet.number===state.selected?0:-1;
      const pin=row.querySelector('.pin-button'),pinned=A.pins.isPinned(packet.number);
      pin.classList.toggle('active',pinned);pin.textContent=pinned?'◆':'◇';
      pin.setAttribute('aria-label',pinned?'ピンを解除':'ピン留め');
      desired.push(row);
    }
    if(end<state.packets.length)desired.push(spacer((state.packets.length-end)*ROW_HEIGHT));
    // Retain existing row/cell nodes: live appends must not destroy text selections or focus.
    let cursor=body.firstChild;
    for(const row of desired) {
      if(row===cursor)cursor=cursor.nextSibling;
      else body.insertBefore(row,cursor);
    }
    while(cursor){const next=cursor.nextSibling;if(cursor.contains(document.activeElement))scroll.focus({preventScroll:true});cursor.remove();cursor=next;}
    document.querySelector('.packet-table').setAttribute('aria-rowcount',String(state.packets.length+1));
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
    row.dataset.capture = state.active?.id || "";
    row.tabIndex = packet.number === state.selected ? 0 : -1;
    row.setAttribute("role", "row");
    row.setAttribute("aria-selected", String(packet.number === state.selected));
    const pinCell = el("td"), pinned = A.pins.isPinned(packet.number);
    const pin = button(pinned ? "◆" : "◇", event => {
      event.stopPropagation(); A.pins.togglePin(packet);
    }, "pin-button" + (pinned ? " active" : ""));
    pin.setAttribute("aria-label", pinned ? "ピンを解除" : "ピン留め");
    pin.tabIndex=-1;
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
    return row;
  }
  function valueCell(packet, field) {
    const cell = el("td", "value-cell");
    cell.setAttribute("role","gridcell");
    cell.dataset.field = field; cell.dataset.scope = "column";
    const value = String(packet[field] ?? ""), span = el("span", "value-text", value);
    cell.append(span); cell.title = value;
    return cell;
  }
  async function selectPacket(number, options = {}) {
    if (!state.active || !number) return;
    state.selected = number;
    if(options.keyboard){scrollToPacket(number);renderVirtualRows(true);$("packet-rows").querySelector(`[data-number="${number}"]`)?.focus({preventScroll:true});}
    document.querySelectorAll('#packet-rows tr[data-number]').forEach(row => {
      row.classList.toggle('selected', Number(row.dataset.number) === number);
      row.setAttribute('aria-selected', String(Number(row.dataset.number) === number));
      row.tabIndex=Number(row.dataset.number)===number?0:-1;
    });
    if (options.scroll !== false) scrollToPacket(number);
    state.detailController?.abort();
    const controller = new AbortController(); state.detailController = controller;
    const captureId = state.active.id;
    state.selectedDetail = null;
    A.viewer.clearDetail();
    const loading = A.loading.begin("detail", "パケット詳細を読み込み中…", `#${number}`);
    $("selected-number").textContent = "#" + number;
    $("packet-details").replaceChildren(el("div", "empty-detail", "解析中..."));
    try {
      const detail = await A.local.query(captureId, "detail", {number}, controller.signal, loading.progress);
      if (controller !== state.detailController || state.active?.id !== captureId) return;
      state.selectedDetail = detail; state.compareDetails.set(number, detail);
      A.viewer.renderDetails(detail.layers); A.viewer.renderHex(detail.hex); A.pins.renderPins();
      A.status(`#${number} の詳細を表示`);
    } catch (error) {
      if (!controller.signal.aborted) {
        loading.fail(error.message);
        $("packet-details").replaceChildren(el("div", "empty-detail", error.message));
        A.status(error.message, "error");
      }
    } finally { loading.end(); }
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
  // One delegated handler also works when focus stays on the scroll viewport.
  $('packet-scroll').addEventListener('keydown',event=>{
    if(event.target.closest('button,input,select,textarea,a'))return;
    const records=state.packets;if(!records.length)return;
    const index=records.findIndex(packet=>packet.number===state.selected);
    const page=Math.max(1,Math.floor(($('packet-scroll').clientHeight-26)/(A.layout?.rowHeight()||24))-1);
    const moves={ArrowUp:index<0?0:index-1,ArrowDown:index<0?0:index+1,Home:0,End:records.length-1,
      PageUp:Math.max(0,index)-page,PageDown:Math.max(0,index)+page};
    if(Object.hasOwn(moves,event.key)){
      event.preventDefault();const next=records[Math.max(0,Math.min(records.length-1,moves[event.key]))];
      void selectPacket(next.number,{keyboard:true});return;
    }
    const packet=records[Math.max(0,index)];
    if(event.key==='Enter'){event.preventDefault();void selectPacket(packet.number,{keyboard:true});}
    else if(event.key===' '){event.preventDefault();A.pins.togglePin(packet);}
    else if(event.key==='ContextMenu'||(event.shiftKey&&event.key==='F10')){
      event.preventDefault();scrollToPacket(packet.number);renderVirtualRows(true);
      const row=$('packet-rows').querySelector(`[data-number="${packet.number}"]`);
      const cell=row.querySelector('[data-field="info"]'),r=row.getBoundingClientRect();
      A.filters.showPacketMenu(packet,'info',cell,r.left+40,r.top+20);
    }else if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='c'&&window.getSelection()?.isCollapsed!==false){
      event.preventDefault();A.clipboard.copy(Object.keys(A.columns).map(key=>packet[key]??'').join('\t'));
    }
  });
  document.querySelector('.packet-table').setAttribute('role','grid');
  Object.assign(A.viewer, { renderVirtualRows, selectPacket });
})();
