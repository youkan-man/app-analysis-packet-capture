/* Evidence-based communication hierarchy; the anchor is independent of detail selection. */
(() => {
  'use strict';
  const A = window.PacketApp, {$, el, button, state} = A;
  let controller = null, data = null;
  const endpoint = e => e.port ? `${e.address}:${e.port}` : e.address;
  function close() {
    controller?.abort(); controller = null;
    $('relations-panel').hidden = true;
    $('workspace').classList.remove('relations-open');
    $('open-relations').setAttribute('aria-expanded', 'false');
    A.layout?.refresh();
  }
  async function open(number = state.selected) {
    if (!number || !state.active) return;
    const capture = state.active.id;
    controller?.abort(); const request = new AbortController(); controller = request;
    A.filters.toggleFilter(false);
    $('relations-panel').hidden = false; $('workspace').classList.add('relations-open');
    $('open-relations').setAttribute('aria-expanded', 'true');
    $('relations-content').replaceChildren(el('div', 'empty-detail', `#${number} の通信を解析中...`));
    A.layout?.refresh();
    try {
      const result = await A.api(`/api/captures/${capture}/packets/${number}/relations`, {signal: request.signal});
      if (controller !== request || state.active?.id !== capture) return;
      data = result;
      for (const packet of data.packets) {
        if (!state.packetCache.has(packet.number)) state.packetCache.set(packet.number, {
          ...packet, source: packet.source.address, destination: packet.destination.address, length: '', fields: {},
        });
      }
      render();
    } catch (error) {
      if (!request.signal.aborted) $('relations-content').replaceChildren(el('div', 'empty-detail', error.message));
    }
  }
  function record(packet, relation = null) {
    const row = el('div', 'relation-record'); row.dataset.number = String(packet.number);
    row.classList.toggle('anchor-record', packet.number === data.anchor);
    row.classList.toggle('selected-record', packet.number === state.selected);
    const caption = `#${packet.number}  ${packet.direction === 'tx' ? '送信 →' : packet.direction === 'rx' ? '← 受信' : 'その他'}  ${packet.time} s`;
    const select = button(caption, () => {
      A.viewer.selectPacket(packet.number);
      $('relations-content').querySelectorAll('.relation-record').forEach(line => line.classList.toggle('selected-record', Number(line.dataset.number) === packet.number));
    }, 'relation-jump');
    row.append(select);
    if (relation) {
      const suffix = relation.delta_ms == null ? '' : ` · ${relation.delta_ms} ms`;
      const label = el('span', 'relation-kind', relation.label + suffix);
      label.title = relation.evidence.join(', '); row.append(label);
    }
    row.append(el('div', 'relation-info', `${packet.protocol} · ${packet.info}`));
    const secondary = data.relations.filter(edge => edge.child === packet.number && edge !== relation);
    if (secondary.length) {
      const links = el('div', 'relation-links');
      secondary.forEach(edge => links.append(button(`${edge.label} #${edge.parent}`, () => A.viewer.selectPacket(edge.parent), 'text-button')));
      row.append(links);
    }
    return row;
  }
  function render() {
    const content = $('relations-content'); content.replaceChildren();
    const title = data.stream ? `${data.stream.transport.toUpperCase()} ストリーム ${data.stream.index}` : 'フレーム参照';
    content.append(el('div', 'relation-anchor', `基準 #${data.anchor} · ${title}`),
      el('div', 'relation-endpoints', `${endpoint(data.origin)} ⇄ ${endpoint(data.peer)}`),
      el('div', 'relation-counts', `送信 ${data.counts.tx} / 受信 ${data.counts.rx} / 全 ${data.counts.total}`));
    const stack = el('div', 'protocol-stack');
    data.protocol_stack.filter(Boolean).forEach(name => stack.append(el('span', '', name)));
    content.append(stack);
    const byNumber = new Map(data.packets.map(packet => [packet.number, packet]));
    const parents = new Map(), children = new Map();
    const priority = {response: 0, reassembly: 1, ack: 2, duplicate_ack: 3};
    [...data.relations].sort((a,b) => priority[a.kind] - priority[b.kind]).forEach(edge => {
      if (edge.available && edge.parent < edge.child && !parents.has(edge.child)) {
        parents.set(edge.child, edge);
        const list = children.get(edge.parent) || []; list.push(edge); children.set(edge.parent, list);
      }
    });
    const tree = el('div', 'relation-tree');
    function append(parent, packet, edge, depth) {
      const following = children.get(packet.number) || [];
      if (depth > 64) {parent.append(record(packet, edge)); return;}
      if (!following.length) {parent.append(record(packet, edge)); return;}
      const group = el('details', 'relation-group'); group.open = true;
      const summary = el('summary', '', `#${packet.number} → 関連 ${following.length}件`);
      group.append(summary, record(packet, edge));
      const nested = el('div', 'relation-children');
      following.sort((a,b) => a.child-b.child).forEach(next => append(nested, byNumber.get(next.child), next, depth+1));
      group.append(nested); parent.append(group);
    }
    data.packets.filter(packet => !parents.has(packet.number)).forEach(packet => append(tree, packet, null, 0));
    content.append(tree);
    data.warnings.forEach(text => content.append(el('div', 'relation-warning', text)));
  }
  function init() {
    const panel = el('aside', 'relations-panel'); panel.id = 'relations-panel'; panel.hidden = true;
    panel.setAttribute('aria-label', '送受信の階層');
    const header = el('div', 'drawer-head');
    const closeButton = button('×', close, 'icon-button'); closeButton.id = 'close-relations'; closeButton.setAttribute('aria-label','通信階層を閉じる');
    header.append(el('strong','', '送受信の階層'), closeButton);
    const content = el('div', 'relations-content'); content.id = 'relations-content'; panel.append(header, content);
    $('workspace').append(panel);
    const control = button('通信階層', () => open(), 'button'); control.id = 'open-relations';
    control.setAttribute('aria-expanded', 'false'); control.setAttribute('aria-controls', panel.id);
    $('open-compare').before(control);
    document.addEventListener('keydown', event => {if (event.key === 'Escape' && !panel.hidden) close();});
    const originalToggle = A.filters.toggleFilter;
    A.filters.toggleFilter = value => { if (value !== false) close(); originalToggle(value); A.layout?.refresh(); };
    const originalOpen = A.viewer.openCapture;
    A.viewer.openCapture = capture => {close(); return originalOpen(capture);};
  }
  A.relations = {init, open, close};
})();
