/* Per-capture pin snapshots and field-by-field record comparison. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, el, button, status, api, persistPins, MAX_COMPARE_FIELDS } = A;

  function isPinned(number) {
    return state.pins.some(pin => pin.number === number);
  }
  function pinSnapshot(packet) {
    return {
      number: packet.number, time: packet.time, source: packet.source,
      destination: packet.destination, protocol: packet.protocol,
      length: packet.length, info: packet.info,
    };
  }
  function togglePin(packet) {
    const index = state.pins.findIndex(pin => pin.number === packet.number);
    if (index >= 0) state.pins.splice(index, 1);
    else state.pins.push(pinSnapshot(packet));
    persistPins();
    renderPins();
    A.viewer.renderVirtualRows(true);
    status(index >= 0 ? `#${packet.number} のピンを解除` : `#${packet.number} をピン留め`);
  }
  function renderPins() {
    $("pin-count").textContent = String(state.pins.length);
    $("open-compare").disabled = state.pins.length < 2;
    $("compare-pins").disabled = state.pins.length < 2;
    const bar = $("pin-bar");
    const container = $("pin-chips");
    container.replaceChildren();
    for (const pin of state.pins) {
      const chip = el("div", "pin-chip" + (pin.number === state.selected ? " active" : ""));
      chip.append(
        button(`#${pin.number} ${pin.protocol}`, () => A.viewer.selectPacket(pin.number)),
        button("×", () => togglePin(pin)),
      );
      container.append(chip);
    }
    bar.hidden = !state.pins.length;
  }
  function clearPins() {
    state.pins = [];
    persistPins();
    renderPins();
    A.viewer.renderVirtualRows(true);
    closeCompare();
    status("ピンをすべて解除しました");
  }
  async function openCompare() {
    if (state.pins.length < 2 || !state.active) return;
    $("compare-panel").hidden = false;
    $("compare-progress").textContent = "詳細を取得中...";
    $("compare-table").replaceChildren();
    try {
      await Promise.all(state.pins.map(async pin => {
        if (!state.compareDetails.has(pin.number)) {
          state.compareDetails.set(pin.number,
            await api(`/api/captures/${state.active.id}/packets/${pin.number}`));
        }
      }));
      renderComparison();
      $("compare-progress").textContent = `${state.pins.length}件`;
    } catch (error) {
      $("compare-progress").textContent = error.message;
      status("比較: " + error.message, "error");
    }
  }
  function closeCompare() {
    $("compare-panel").hidden = true;
  }
  function flattenLayers(layers) {
    const output = new Map();
    let count = 0;
    function visit(value, path, depth) {
      if (count >= MAX_COMPARE_FIELDS || depth > 12) return;
      if (value !== null && typeof value === "object") {
        const entries = Array.isArray(value)
          ? value.map((item, index) => [String(index + 1), item]) : Object.entries(value);
        for (const [key, child] of entries) {
          if (!key.endsWith("_raw")) visit(child, path ? `${path}.${key}` : key, depth + 1);
        }
      } else if (path) {
        output.set(path, String(value ?? ""));
        count++;
      }
    }
    visit(layers, "", 0);
    return output;
  }
  function renderComparison() {
    const table = $("compare-table");
    table.replaceChildren();
    const maps = state.pins.map(pin => flattenLayers(
      state.compareDetails.get(pin.number)?.layers || {}));
    const summaries = [
      ["概要.No.", pin => pin.number], ["概要.Time", pin => pin.time],
      ["概要.Source", pin => pin.source], ["概要.Destination", pin => pin.destination],
      ["概要.Protocol", pin => pin.protocol], ["概要.Length", pin => pin.length],
      ["概要.Info", pin => pin.info],
    ];
    const keys = Array.from(new Set(maps.flatMap(map => Array.from(map.keys()))))
      .sort().slice(0, MAX_COMPARE_FIELDS);
    const head = el("thead");
    const headerRow = el("tr");
    headerRow.append(el("th", "", "フィールド"));
    state.pins.forEach(pin => headerRow.append(el("th", "", `#${pin.number} ${pin.protocol}`)));
    head.append(headerRow);
    table.append(head);
    const body = el("tbody");
    function addRow(label, values) {
      const row = el("tr");
      const normalized = values.map(value => String(value ?? ""));
      const different = new Set(normalized).size > 1;
      row.className = different ? "" : "same-row";
      row.hidden = $("diff-only").checked && !different;
      row.append(el("td", "", label));
      normalized.forEach(value => row.append(el("td", different ? "different" : "", value)));
      body.append(row);
    }
    summaries.forEach(([label, getter]) => addRow(label, state.pins.map(getter)));
    keys.forEach(key => addRow(key, maps.map(map => map.get(key) || "")));
    table.append(body);
  }

  A.pins = {
    isPinned, togglePin, renderPins, clearPins,
    openCompare, closeCompare, renderComparison,
  };
})();
