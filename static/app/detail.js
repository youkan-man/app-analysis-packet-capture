/* One field/byte selection model shared by tree, hex, ASCII and copy commands. */
(() => {
  'use strict';
  const A = window.PacketApp;
  const {$, el, state} = A;
  const model = {hex: '', fields: [], elements: new Map(), selection: null, field: null,
    anchor: 0, dragging: false, window: ''};
  const rowHeight = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--byte-row-height')) || 21;
  const rangeOf = field => field?.byte_range;

  function clearDetail() {
    model.hex = ''; model.fields = []; model.elements.clear(); model.selection = null; model.field = null;
    $('selected-number').textContent = '—'; $('byte-count').textContent = '0 B';
    $('packet-details').replaceChildren(el('div', 'empty-detail', 'パケットを選択してください'));
    $('packet-bytes').replaceChildren(); updateControls();
  }
  function renderDetails() {
    model.hex = state.selectedDetail?.hex || '';
    model.fields = []; model.elements.clear(); model.field = null; model.selection = null;
    const tree = $('packet-details'); tree.replaceChildren();
    function append(parent, field, depth) {
      model.fields.push(field);
      const hasChildren = field.children.length > 0;
      const group = hasChildren ? el('details') : null;
      if (group) group.open = depth === 0 && field.name !== 'frame';
      const line = el(hasChildren ? 'summary' : 'div', 'detail-leaf field-row');
      line.tabIndex = 0;
      line.dataset.fieldId = field.id; line.dataset.field = field.name;
      line.dataset.scope = 'wireshark'; line.dataset.value = field.value;
      line.title = field.name + (field.byte_range ? ` · ${field.byte_range.offset}–${field.byte_range.offset + field.byte_range.length - 1}` : ' · 対応バイトなし');
      const label = el('span', 'detail-value value-text', field.display_value);
      line.append(label);
      model.elements.set(field.id, line);
      const select = () => selectField(field, true);
      line.addEventListener('click', select);
      line.addEventListener('contextmenu', event => {
        event.preventDefault(); event.stopPropagation(); select();
        A.filters.showDetailMenu(field.name, field.value, line, event.clientX, event.clientY, field);
      });
      line.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); select();}
        if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
          event.preventDefault(); event.stopPropagation(); select();
          const r = line.getBoundingClientRect();
          A.filters.showDetailMenu(field.name, field.value, line, r.left + 12, r.bottom, field);
        }
        if ((event.ctrlKey || event.metaKey) && event.key === 'c' && window.getSelection()?.isCollapsed) {
          event.preventDefault(); A.clipboard.copy(field.value);
        }
      });
      if (field.kind === 'string') line.addEventListener('mouseup', event => A.filters.selectionFromElement(
        event, label, {scope: 'wireshark', field: field.name, kind: field.kind}));
      if (group) {group.append(line); parent.append(group); field.children.forEach(child => append(group, child, depth + 1));}
      else parent.append(line);
    }
    (state.selectedDetail?.fields || []).forEach(field => append(tree, field, 0));
    if (!tree.children.length) tree.append(el('div', 'empty-detail', 'プロトコル詳細はありません'));
    updateControls();
  }
  function selectField(field, scrollBytes = false) {
    model.field = field;
    const range = rangeOf(field);
    model.selection = range ? {start: range.offset, end: range.offset + range.length - 1} : null;
    model.elements.forEach((line, id) => line.classList.toggle('selected-field', id === field.id));
    if (scrollBytes && range) {
      const viewport = $('packet-bytes').parentElement;
      const top = Math.floor(range.offset / 16) * rowHeight();
      if (top < viewport.scrollTop || top > viewport.scrollTop + viewport.clientHeight - rowHeight() * 2) viewport.scrollTop = Math.max(0, top - 40);
    }
    renderByteWindow(true); updateControls();
  }
  function selectBytes(start, end = start) {
    const max = model.hex.length / 2 - 1;
    if (max < 0) return;
    const lo = Math.max(0, Math.min(start, end, max)), hi = Math.min(max, Math.max(start, end, 0));
    model.selection = {start: lo, end: hi};
    const candidates = model.fields.filter(field => {
      const range = rangeOf(field);
      return range && range.offset <= lo && range.offset + range.length > hi;
    }).sort((a, b) => Number(a.hidden) - Number(b.hidden) || a.byte_range.length - b.byte_range.length ||
      b.id.split('.').length - a.id.split('.').length);
    model.field = candidates[0] || null;
    model.elements.forEach((line, id) => line.classList.toggle('selected-field', id === model.field?.id));
    const line = model.elements.get(model.field?.id);
    if (line) {
      for (let parent = line.parentElement; parent && parent !== $('packet-details'); parent = parent.parentElement) {
        if (parent.tagName === 'DETAILS') parent.open = true;
      }
      const viewport = $('packet-details'), r = line.getBoundingClientRect(), v = viewport.getBoundingClientRect();
      if (r.top < v.top || r.bottom > v.bottom) viewport.scrollTop += r.top - v.top - 20;
    }
    paintBytes(); updateControls();
  }
  function renderHex(hex) {
    model.hex = /^(?:[0-9a-fA-F]{2})*$/.test(hex || '') ? (hex || '').toLowerCase() : '';
    $('byte-count').textContent = `${model.hex.length / 2} B`;
    model.window = ''; renderByteWindow(true); updateControls();
  }
  function renderByteWindow(force = false) {
    const container = $('packet-bytes'), viewport = container.parentElement;
    const rows = Math.ceil(model.hex.length / 32), h = rowHeight();
    const start = Math.min(rows, Math.max(0, Math.floor((viewport.scrollTop - 24) / h) - 6));
    const end = Math.min(rows, start + Math.ceil((viewport.clientHeight || 200) / h) + 15);
    const key = `${start}:${end}:${model.hex.length}`;
    if (!force && model.window === key) return;
    model.window = key;
    container.replaceChildren();
    function spacer(count) { const node = el('div', 'byte-spacer'); node.style.height = `${count * h}px`; container.append(node); }
    spacer(start);
    for (let r = start; r < end; r++) {
      const row = el('div', 'hex-row');
      row.append(el('span', 'hex-offset', (r * 16).toString(16).padStart(4, '0')));
      const hex = el('span', 'hex-digits'), ascii = el('span', 'hex-ascii');
      for (let j = 0; j < 16; j++) {
        const offset = r * 16 + j, value = model.hex.slice(offset * 2, offset * 2 + 2);
        const b = el('span', 'hex-byte', value || '  ');
        const code = parseInt(value, 16);
        const a = el('span', 'ascii-byte', value ? (code >= 32 && code <= 126 ? String.fromCharCode(code) : '.') : ' ');
        if (value) {b.dataset.offset = a.dataset.offset = String(offset); b.title = a.title = `0x${offset.toString(16)}`;}
        hex.append(b); ascii.append(a);
      }
      row.append(hex, ascii); container.append(row);
    }
    spacer(rows - end); paintBytes();
  }
  function paintBytes() {
    $('packet-bytes').querySelectorAll('[data-offset]').forEach(node => {
      const offset = Number(node.dataset.offset);
      node.classList.toggle('byte-selected', Boolean(model.selection && offset >= model.selection.start && offset <= model.selection.end));
    });
  }
  function byteText(all = false, compact = false) {
    const {start, end} = !all && model.selection ? model.selection : {start: 0, end: model.hex.length / 2 - 1};
    const hex = model.hex.slice(start * 2, (end + 1) * 2);
    return compact ? hex : (hex.match(/../g) || []).join(' ');
  }
  function copyBytes(all = false, compact = false) { return A.clipboard.copy(byteText(all, compact)); }
  function updateControls() {
    if (!$('copy-bytes')) return;
    $('copy-bytes').disabled = !model.hex;
    $('clear-byte-selection').disabled = !model.selection;
    $('byte-selection').textContent = model.selection
      ? `${model.selection.start}–${model.selection.end} · ${model.selection.end - model.selection.start + 1} B`
      : model.field ? '対応バイトなし' : '全バイト';
    $('byte-selection').title = model.field?.display_value || '';
  }
  function init() {
    const head = document.querySelector('.bytes-panel > .panel-head');
    const controls = el('div', 'byte-tools');
    const count = el('span', '', '全バイト'); count.id = 'byte-selection';
    const copy = A.button('バイト列をコピー', () => copyBytes(), 'button'); copy.id = 'copy-bytes';
    const clear = A.button('選択解除', () => { model.selection = null; model.field = null;
      model.elements.forEach(line => line.classList.remove('selected-field')); paintBytes(); updateControls(); }, 'button button-quiet');
    clear.id = 'clear-byte-selection'; controls.append(count, copy, clear); head.after(controls);
    const viewport = $('packet-bytes').parentElement;
    viewport.addEventListener('scroll', () => renderByteWindow());
    new ResizeObserver(() => renderByteWindow(true)).observe(viewport);
    viewport.addEventListener('pointerdown', event => {
      const target = event.target.closest('[data-offset]');
      if (!target || event.button !== 0) return;
      event.preventDefault(); viewport.focus({preventScroll: true});
      const offset = Number(target.dataset.offset);
      model.anchor = event.shiftKey && model.selection ? model.anchor : offset;
      model.dragging = true; viewport.setPointerCapture(event.pointerId); selectBytes(model.anchor, offset);
    });
    viewport.addEventListener('pointermove', event => {
      if (!model.dragging) return;
      const node = document.elementFromPoint(event.clientX, event.clientY)?.closest('[data-offset]');
      if (node && viewport.contains(node)) selectBytes(model.anchor, Number(node.dataset.offset));
    });
    const stop = event => {model.dragging = false; if (viewport.hasPointerCapture(event.pointerId)) viewport.releasePointerCapture(event.pointerId);};
    viewport.addEventListener('pointerup', stop); viewport.addEventListener('pointercancel', stop);
    viewport.addEventListener('copy', event => {
      if (!model.hex || !event.clipboardData) return;
      event.preventDefault(); event.clipboardData.setData('text/plain', byteText());
    });
    viewport.addEventListener('keydown', event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c') {
        event.preventDefault(); copyBytes(); return;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
        event.preventDefault(); selectBytes(0, model.hex.length / 2 - 1);
      }
      if (['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) {
        event.preventDefault();
        const delta = {ArrowLeft:-1,ArrowRight:1,ArrowUp:-16,ArrowDown:16}[event.key];
        const next = Math.max(0, Math.min(model.hex.length / 2 - 1, (model.selection?.end ?? 0) + delta[event.key]));
        if (!event.shiftKey) model.anchor = next;
        selectBytes(model.anchor, next);
      }
    });
    viewport.addEventListener('contextmenu', event => {
      event.preventDefault();
      A.filters.showMenu([
        {heading: 'バイト列'},
        {label: '選択範囲をコピー', run: () => copyBytes()},
        {label: '全バイト列をコピー', run: () => copyBytes(true)},
        {label: '連続16進数でコピー', run: () => copyBytes(false, true)},
      ], event.clientX, event.clientY);
    });
    updateControls();
  }
  A.inspector = {init, selectBytes, copyBytes, byteText};
  Object.assign(A.viewer, {clearDetail, renderDetails, renderHex});
})();
