/* Packet Capture Workbench: all user data stays in textContent and same-origin APIs. */
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const root = $("condition-root");
  const presets = document.querySelectorAll("[data-preset]");
  const storage = { current: "packetcap.current", saved: "packetcap.filters", builder: "packetcap.builder" };
  const defaultRule = () => ({ type: "rule", field: "ip.addr", operator: "==", kind: "address", value: "", negate: false });
  const defaultBuilder = () => ({ type: "group", join: "and", children: [defaultRule()], negate: false });
  const parseStored = (key, fallback) => {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; }
  };
  const state = {
    captures: [], active: null, packets: [], total: 0, page: 1, pageSize: 200,
    filter: "", selected: null, listController: null, detailController: null,
    builder: parseStored(storage.builder, defaultBuilder()), builderBase: "",
    saved: parseStored(storage.saved, []), busy: false
  };
  if (!state.builder || state.builder.type !== "group") state.builder = defaultBuilder();
  if (!Array.isArray(state.saved)) state.saved = [];

  function dom(tag, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
  }
  function button(label, fn, className = "") {
    const b = dom("button", className, label);
    b.type = "button";
    b.addEventListener("click", fn);
    return b;
  }
  function choice(values, current, onChange, className = "") {
    const select = dom("select", className);
    for (const [value, title] of values) {
      const opt = dom("option", "", title);
      opt.value = value;
      opt.selected = value === current;
      select.append(opt);
    }
    select.addEventListener("change", () => onChange(select.value));
    return select;
  }
  function status(message, mode = "") {
    $("status-message").textContent = message;
    $("status-dot").className = "status-indicator" + (mode ? " " + mode : "");
  }
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: "no-store", ...options });
    if (response.status === 204) return null;
    let value;
    try { value = await response.json(); } catch { throw new Error("サーバーから応答を読み取れません"); }
    if (!response.ok) {
      const detail = Array.isArray(value.detail) ? value.detail.map(x => x.msg).join("; ") : value.detail;
      throw new Error(typeof detail === "string" ? detail : "処理に失敗しました");
    }
    return value;
  }

  function renderSources() {
    $("capture-count").textContent = String(state.captures.length);
    const target = $("capture-list");
    target.replaceChildren();
    for (const capture of state.captures) {
      const item = dom("div", "capture-item" + (state.active?.id === capture.id ? " active" : ""));
      const open = button("", () => openCapture(capture), "capture-open");
      const name = dom("strong", "", capture.filename);
      const size = dom("span", "", capture.format.toUpperCase() + " · " + formatSize(capture.size));
      open.append(name, size);
      open.title = capture.filename;
      const remove = button("×", async () => {
        if (!confirm("このキャプチャを削除しますか？\n" + capture.filename)) return;
        try {
          await api("/api/captures/" + encodeURIComponent(capture.id), { method: "DELETE" });
          if (state.active?.id === capture.id) {
            state.active = null;
            localStorage.removeItem(storage.current);
            resetPacketView();
          }
          await loadCaptures();
        } catch (err) { status(err.message, "error"); }
      }, "remove-capture");
      remove.setAttribute("aria-label", capture.filename + " を削除");
      item.append(open, remove);
      target.append(item);
    }
    if (!state.captures.length) target.append(dom("div", "empty-detail", "ファイルはありません"));
  }
  function resetPacketView() {
    state.packets = []; state.total = 0; state.selected = null;
    $("current-file").textContent = "キャプチャを選択";
    $("source-info").textContent = "ファイルを選択してください";
    renderRows(); clearDetail();
  }
  async function loadCaptures() {
    try {
      const result = await api("/api/captures");
      state.captures = result.items;
      const currentId = state.active?.id || localStorage.getItem(storage.current);
      const selected = state.captures.find(item => item.id === currentId) || state.captures[0];
      if (selected && state.active?.id !== selected.id) {
        await openCapture(selected);
      } else if (!selected) {
        state.active = null; resetPacketView();
      }
      renderSources();
    } catch (err) { status("ファイル一覧: " + err.message, "error"); }
  }
  async function openCapture(capture) {
    state.active = capture;
    state.page = 1;
    state.selected = null;
    localStorage.setItem(storage.current, capture.id);
    $("current-file").textContent = capture.filename;
    $("source-info").textContent = capture.format.toUpperCase() + " · " + formatSize(capture.size);
    renderSources();
    clearDetail();
    await loadPackets();
  }
  async function loadPackets() {
    if (!state.active) { resetPacketView(); return; }
    state.listController?.abort();
    state.detailController?.abort();
    const controller = new AbortController();
    state.listController = controller;
    $("display-filter").classList.remove("invalid");
    $("display-filter").classList.toggle("has-filter", !!state.filter);
    status("パケットを解析中...", "busy");
    const id = state.active.id;
    const params = new URLSearchParams({ page: state.page, limit: state.pageSize, filter: state.filter });
    try {
      const result = await api("/api/captures/" + encodeURIComponent(id) + "/packets?" + params, { signal: controller.signal });
      if (state.listController !== controller || state.active?.id !== id) return;
      state.packets = result.packets;
      state.total = result.total;
      state.selected = null;
      renderRows();
      clearDetail();
      if (state.packets.length) await selectPacket(state.packets[0].number);
      status(state.total + " パケットを表示");
    } catch (err) {
      if (controller.signal.aborted) return;
      state.packets = []; state.total = 0; state.selected = null;
      renderRows(); clearDetail();
      $("display-filter").classList.add("invalid");
      status("フィルター/解析: " + err.message, "error");
    }
  }
  function renderRows() {
    const body = $("packet-rows");
    body.replaceChildren();
    for (const packet of state.packets) {
      const tr = dom("tr", "proto-" + String(packet.protocol || "").toLowerCase().replace(/[^a-z0-9]/g, ""));
      if (packet.number === state.selected) tr.classList.add("selected");
      tr.tabIndex = 0;
      tr.setAttribute("aria-selected", String(packet.number === state.selected));
      tr.title = packet.info;
      const cells = [packet.number, packet.time, packet.source, packet.destination, packet.protocol, packet.length, packet.info];
      for (const value of cells) tr.append(dom("td", "", String(value ?? "")));
      tr.addEventListener("click", () => selectPacket(packet.number));
      tr.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectPacket(packet.number); }
      });
      body.append(tr);
    }
    $("packet-empty").hidden = state.packets.length > 0;
    $("packet-empty").textContent = state.active
      ? (state.filter ? "一致するパケットはありません。" : "パケットがありません。")
      : "PCAP / PCAPNG を開くとパケットが表示されます。";
    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    $("page-number").textContent = state.page + " / " + pages;
    const from = state.total ? (state.page - 1) * state.pageSize + 1 : 0;
    const to = Math.min(state.total, state.page * state.pageSize);
    $("page-range").textContent = from + "–" + to + " / " + state.total;
    $("packet-count").textContent = String(state.total);
    $("status-total").textContent = "表示 " + state.packets.length + " / " + state.total;
    $("prev-page").disabled = state.page <= 1;
    $("next-page").disabled = state.page >= pages;
  }
  async function selectPacket(number) {
    if (!state.active) return;
    state.selected = number;
    const rows = Array.from($("packet-rows").children);
    rows.forEach((row, i) => {
      const selected = state.packets[i]?.number === number;
      row.classList.toggle("selected", selected);
      row.setAttribute("aria-selected", String(selected));
    });
    $("selected-number").textContent = "#" + number;
    state.detailController?.abort();
    const controller = new AbortController();
    state.detailController = controller;
    $("packet-details").replaceChildren(dom("div", "empty-detail", "解析中..."));
    $("packet-bytes").replaceChildren();
    try {
      const detail = await api("/api/captures/" + state.active.id + "/packets/" + number, { signal: controller.signal });
      if (state.detailController !== controller) return;
      renderDetails(detail.layers);
      renderHex(detail.hex);
    } catch (err) {
      if (controller.signal.aborted) return;
      $("packet-details").replaceChildren(dom("div", "empty-detail", err.message));
    }
  }
  function clearDetail() {
    $("selected-number").textContent = "—";
    $("byte-count").textContent = "0 B";
    $("packet-details").replaceChildren(dom("div", "empty-detail", "パケットを選択してください"));
    $("packet-bytes").replaceChildren();
  }
  function renderDetails(layers) {
    const container = $("packet-details");
    container.replaceChildren();
    let rendered = 0;
    function entry(parent, key, value, depth) {
      if (++rendered > 700 || depth > 13) return;
      if (value !== null && typeof value === "object") {
        const block = dom("details");
        if (depth < 2) block.open = true;
        const summary = dom("summary", "", key + (Array.isArray(value) ? " [" + value.length + "]" : ""));
        block.append(summary);
        const items = Array.isArray(value) ? value.map((item, i) => [String(i + 1), item]) : Object.entries(value);
        for (const [name, data] of items) entry(block, name, data, depth + 1);
        parent.append(block);
      } else {
        const line = dom("div", "detail-leaf");
        line.append(dom("span", "detail-key", key + ": "));
        line.append(dom("span", "detail-value", String(value ?? "")));
        parent.append(line);
      }
    }
    for (const [key, value] of Object.entries(layers || {})) entry(container, key, value, 0);
    if (!container.children.length) container.append(dom("div", "empty-detail", "プロトコル詳細はありません"));
  }
  function renderHex(hex) {
    const container = $("packet-bytes");
    container.replaceChildren();
    if (!hex || !/^[a-fA-F0-9]+$/.test(hex)) {
      $("byte-count").textContent = "取得できません";
      container.append(dom("div", "empty-detail", "バイトデータがありません"));
      return;
    }
    const bytes = hex.match(/.{2}/g) || [];
    $("byte-count").textContent = bytes.length + " B";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const line = dom("div", "hex-row");
      line.append(dom("span", "hex-offset", i.toString(16).padStart(4, "0")));
      line.append(dom("span", "hex-digits", chunk.join(" ").padEnd(47, " ")));
      line.append(dom("span", "hex-ascii", chunk.map(n => {
        const code = parseInt(n, 16);
        return code >= 32 && code <= 126 ? String.fromCharCode(code) : ".";
      }).join("")));
      container.append(line);
    }
  }
  async function uploadFiles(files) {
    for (const file of files) {
      if (!file) continue;
      status(file.name + " を取り込み中...", "busy");
      const form = new FormData();
      form.append("file", file);
      try {
        const capture = await api("/api/captures", { method: "POST", body: form });
        state.active = null;
        localStorage.setItem(storage.current, capture.id);
        await loadCaptures();
        status(file.name + " を取り込みました");
      } catch (err) { status(file.name + ": " + err.message, "error"); }
    }
    $("file-input").value = "";
  }

  function applyExpression(expression) {
    state.filter = expression.trim();
    $("display-filter").value = state.filter;
    state.page = 1;
    presets.forEach(b => b.classList.toggle("active", b.dataset.preset === state.filter));
    loadPackets();
  }
  function persistBuilder() {
    try { localStorage.setItem(storage.builder, JSON.stringify(state.builder)); } catch { /* storage may be disabled */ }
    previewBuilder();
  }
  function compileLocal(node, depth = 0) {
    if (!node || depth > 6) throw new Error("グループの階層を確認してください");
    let result;
    if (node.type === "group") {
      if (!["and", "or"].includes(node.join) || !Array.isArray(node.children)) throw new Error("結合条件が不正です");
      const children = node.children.map(child => compileLocal(child, depth + 1)).filter(Boolean);
      result = children.length ? "(" + children.join(node.join === "or" ? " || " : " && ") + ")" : "";
    } else if (node.type === "rule") {
      const field = String(node.field || "").trim();
      const op = node.operator;
      if (!/^[A-Za-z_][A-Za-z0-9_.]*(?:#[0-9]+)?$/.test(field)) throw new Error("フィールドを入力してください");
      if (op === "exists") result = field;
      else {
        const value = String(node.value || "").trim();
        if (!value) throw new Error(field + " の比較値を入力してください");
        if (!["==", "!=", ">", ">=", "<", "<=", "contains", "matches"].includes(op)) throw new Error("演算子が不正です");
        const kind = node.kind || "string";
        if ((op === "contains" || op === "matches") && kind !== "string") throw new Error("文字列検索には値の種類「文字列」を選択してください");
        if (kind === "number" && !/^-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)$/.test(value)) throw new Error("数値の形式が不正です");
        if (kind === "address" && !/^[0-9A-Fa-f:.]+(?:\/\d{1,3})?$/.test(value)) throw new Error("アドレスの形式が不正です");
        result = field + " " + op + " " + (kind === "string" ? JSON.stringify(value) : value);
      }
    } else throw new Error("不明な条件です");
    return node.negate && result ? "!(" + result + ")" : result;
  }
  function previewBuilder() {
    try {
      const expr = compileLocal(state.builder);
      const total = state.builderBase && expr ? "(" + state.builderBase + ") && " + expr : state.builderBase || expr;
      $("visual-expression").value = total;
      $("builder-error").textContent = "";
      $("apply-builder").disabled = !total;
    } catch (err) {
      $("visual-expression").value = "";
      $("builder-error").textContent = err.message;
      $("apply-builder").disabled = true;
    }
  }
  const OPERATORS = [
    ["==", "等しい ="], ["!=", "等しくない ≠"], [">", "より大きい >"], [">=", "以上 ≥"],
    ["<", "より小さい <"], ["<=", "以下 ≤"], ["contains", "含む"], ["matches", "正規表現"], ["exists", "存在する"]
  ];
  const KINDS = [["string", "文字列"], ["number", "数値"], ["address", "IP/MAC"]];
  let fieldTimer = null;
  const suggestions = dom("datalist");
  suggestions.id = "field-suggestions";
  document.body.append(suggestions);
  async function fillSuggestions(value) {
    try {
      const result = await api("/api/fields?q=" + encodeURIComponent(value));
      suggestions.replaceChildren();
      for (const entry of result.items.slice(0, 40)) {
        const option = dom("option");
        option.value = entry.name;
        option.label = entry.label + " (" + entry.type + ")";
        suggestions.append(option);
      }
    } catch { /* typed filters remain available even when metadata lookup fails */ }
  }
  function renderNode(node, parent, depth = 0, onRemove = null) {
    if (node.type === "group") {
      const wrap = dom("div", "group" + (depth ? " nested" : ""));
      const header = dom("div", "group-header");
      header.append(choice([["and", "すべて AND"], ["or", "いずれか OR"]], node.join || "and", value => {
        node.join = value; persistBuilder();
      }, "group-join"));
      const negative = dom("label", "negate-wrap");
      const checkbox = dom("input");
      checkbox.type = "checkbox"; checkbox.checked = !!node.negate;
      checkbox.addEventListener("change", () => { node.negate = checkbox.checked; persistBuilder(); });
      negative.append(checkbox, dom("span", "", "NOT"));
      header.append(negative);
      header.append(button("＋ 条件", () => {
        node.children.push(defaultRule()); renderBuilder();
      }));
      if (depth < 5) header.append(button("＋ グループ", () => {
        node.children.push({ type: "group", join: "or", children: [defaultRule()], negate: false }); renderBuilder();
      }));
      if (onRemove) header.append(button("×", onRemove, "group-delete"));
      wrap.append(header);
      for (let i = 0; i < node.children.length; i++) {
        const index = i;
        renderNode(node.children[i], wrap, depth + 1, () => {
          node.children.splice(index, 1); renderBuilder();
        });
      }
      parent.append(wrap);
    } else if (node.type === "rule") {
      const wrap = dom("div", "rule");
      const fieldLine = dom("div", "field-box");
      const field = dom("input");
      field.type = "text"; field.value = node.field ?? ""; field.placeholder = "例: ip.src";
      field.setAttribute("aria-label", "フィールド");
      field.setAttribute("list", "field-suggestions");
      field.addEventListener("input", () => {
        node.field = field.value; persistBuilder();
        clearTimeout(fieldTimer);
        fieldTimer = setTimeout(() => fillSuggestions(field.value), 200);
      });
      field.addEventListener("focus", () => fillSuggestions(field.value));
      const neg = dom("label", "negate-wrap");
      const negInput = dom("input"); negInput.type = "checkbox"; negInput.checked = !!node.negate;
      negInput.addEventListener("change", () => { node.negate = negInput.checked; persistBuilder(); });
      neg.append(negInput, dom("span", "", "NOT"));
      fieldLine.append(field, neg);
      wrap.append(fieldLine);
      const op = choice(OPERATORS, node.operator || "==", value => {
        node.operator = value;
        if ((value === "contains" || value === "matches") && node.kind !== "string") node.kind = "string";
        renderBuilder();
      }, "rule-op");
      wrap.append(op);
      if (node.operator !== "exists") {
        const value = dom("input", "rule-value");
        value.type = "text"; value.value = node.value ?? ""; value.placeholder = "比較値";
        value.setAttribute("aria-label", "比較値");
        value.addEventListener("input", () => { node.value = value.value; persistBuilder(); });
        wrap.append(value);
        wrap.append(choice(KINDS, node.kind || "string", kind => {
          node.kind = kind; persistBuilder();
        }, "rule-kind"));
      }
      wrap.append(button("×", onRemove, "remove-rule"));
      parent.append(wrap);
    }
  }
  function renderBuilder() {
    root.replaceChildren();
    renderNode(state.builder, root);
    persistBuilder();
  }
  async function applyBuilder() {
    previewBuilder();
    if (!$("visual-expression").value) return;
    try {
      const compiled = await api("/api/filters/compile", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node: state.builder })
      });
      const total = state.builderBase && compiled.expression
        ? "(" + state.builderBase + ") && " + compiled.expression
        : state.builderBase || compiled.expression;
      $("builder-error").textContent = "";
      applyExpression(total);
    } catch (err) {
      $("builder-error").textContent = err.message;
      status("条件を修正してください: " + err.message, "error");
    }
  }
  function toggleBuilder(open) {
    const show = typeof open === "boolean" ? open : $("filter-builder").hidden;
    $("filter-builder").hidden = !show;
    $("workspace").classList.toggle("builder-open", show);
    $("toggle-builder").setAttribute("aria-expanded", String(show));
    $("toggle-builder").classList.toggle("button-primary", show);
    if (show) renderBuilder();
    else $("toggle-builder").focus();
  }
  function renderSaved() {
    const select = $("saved-filters");
    select.replaceChildren();
    const empty = dom("option", "", "保存済みフィルター");
    empty.value = ""; select.append(empty);
    for (const item of state.saved) {
      const option = dom("option", "", item.name);
      option.value = item.expression;
      select.append(option);
    }
  }
  function wireEvents() {
    $("open-file").addEventListener("click", () => $("file-input").click());
    $("drop-target").addEventListener("click", () => $("file-input").click());
    $("drop-target").addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") $("file-input").click(); });
    $("file-input").addEventListener("change", event => uploadFiles(Array.from(event.target.files)));
    $("refresh").addEventListener("click", loadCaptures);
    $("filter-form").addEventListener("submit", event => {
      event.preventDefault(); applyExpression($("display-filter").value);
    });
    $("clear-filter").addEventListener("click", () => applyExpression(""));
    presets.forEach(btn => btn.addEventListener("click", () => applyExpression(btn.dataset.preset)));
    $("prev-page").addEventListener("click", () => { if (state.page > 1) { state.page--; loadPackets(); } });
    $("next-page").addEventListener("click", () => {
      if (state.page * state.pageSize < state.total) { state.page++; loadPackets(); }
    });
    $("toggle-builder").addEventListener("click", () => toggleBuilder());
    $("close-builder").addEventListener("click", () => toggleBuilder(false));
    $("builder-reset").addEventListener("click", () => {
      state.builder = defaultBuilder(); state.builderBase = ""; renderBuilder();
    });
    $("builder-from-filter").addEventListener("click", () => {
      state.builderBase = state.builderBase ? "" : $("display-filter").value.trim();
      $("builder-from-filter").textContent = state.builderBase ? "手動式の結合を解除" : "現在の式を保持";
      previewBuilder();
    });
    $("apply-builder").addEventListener("click", applyBuilder);
    $("saved-filters").addEventListener("change", event => {
      if (event.target.value) applyExpression(event.target.value);
    });
    $("save-filter").addEventListener("click", () => {
      const expression = $("display-filter").value.trim();
      if (!expression) { status("保存する式を入力してください", "error"); return; }
      const name = prompt("フィルター名", expression);
      if (name === null) return;
      const label = name.trim().slice(0, 60);
      if (!label) return;
      state.saved = [{ name: label, expression }, ...state.saved.filter(x => x.name !== label)].slice(0, 30);
      localStorage.setItem(storage.saved, JSON.stringify(state.saved));
      renderSaved(); status("フィルターを保存しました");
    });
    document.addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") {
        event.preventDefault(); $("file-input").click();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); $("display-filter").focus(); $("display-filter").select();
      }
      if (event.key === "Escape" && !$("filter-builder").hidden) toggleBuilder(false);
    });
    let dragDepth = 0;
    document.addEventListener("dragenter", event => {
      if (!event.dataTransfer?.types.includes("Files")) return;
      event.preventDefault(); dragDepth++; $("drag-overlay").hidden = false;
    });
    document.addEventListener("dragover", event => {
      if (!event.dataTransfer?.types.includes("Files")) return;
      event.preventDefault();
    });
    document.addEventListener("dragleave", event => {
      if (--dragDepth <= 0) { dragDepth = 0; $("drag-overlay").hidden = true; }
    });
    document.addEventListener("drop", event => {
      event.preventDefault(); dragDepth = 0; $("drag-overlay").hidden = true;
      if (event.dataTransfer?.files?.length) uploadFiles(Array.from(event.dataTransfer.files));
    });
  }

  wireEvents();
  renderSaved();
  renderBuilder();
  $("filter-builder").hidden = true;
  loadCaptures();
})();