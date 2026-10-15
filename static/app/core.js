/* Shared state and dependency-free utilities for Packet Capture Workbench. */
(() => {
  "use strict";
  const A = window.PacketApp = window.PacketApp || {};
  const $ = id => document.getElementById(id);
  const storage = Object.freeze({
    current: "packetcap.current",
    saved: "packetcap.savedFilters.v2",
    viewPrefix: "packetcap.view.v2.",
    pinsPrefix: "packetcap.pins.v2.",
  });
  const columns = Object.freeze({
    number: { label: "No.", type: "number" },
    time: { label: "Time", type: "number" },
    source: { label: "Source", type: "string" },
    destination: { label: "Destination", type: "string" },
    protocol: { label: "Protocol", type: "string" },
    length: { label: "Length", type: "number" },
    info: { label: "Info", type: "string" },
  });
  const stringOperators = Object.freeze([
    ["equals", "等しい"], ["not_equals", "等しくない"],
    ["contains", "含む"], ["not_contains", "含まない"],
    ["starts_with", "先頭一致"], ["ends_with", "末尾一致"],
  ]);
  const numberOperators = Object.freeze([
    ["equals", "等しい"], ["not_equals", "等しくない"],
    ["greater", "より大きい"], ["greater_equal", "以上"],
    ["less", "より小さい"], ["less_equal", "以下"],
  ]);
  const nativeOperators = Object.freeze([
    ["equals", "等しい"], ["not_equals", "等しくない"],
    ["contains", "含む"], ["not_contains", "含まない"],
    ["exists", "存在する"], ["not_exists", "存在しない"],
  ]);
  const operatorLabels = Object.freeze(Object.fromEntries([
    ...stringOperators, ...numberOperators, ...nativeOperators,
  ]));
  const defaultView = () => ({ groups: [], raw: "", context: 0 });
  const parseStored = (key, fallback) => {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; }
    catch { return fallback; }
  };
  const clone = value => JSON.parse(JSON.stringify(value));
  const state = {
    captures: [], active: null, packets: [], packetCache: new Map(),
    total: 0, matched: 0, displayed: 0, selected: null, selectedDetail: null,
    listController: null, detailController: null,
    view: defaultView(), pins: [], saved: parseStored(storage.saved, []),
    menuReturnFocus: null, selection: null, compareDetails: new Map(), filterOpen: false,
  };
  if (!Array.isArray(state.saved)) state.saved = [];

  function el(tag, className = "", text = "") {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }
  function button(text, handler, className = "") {
    const node = el("button", className, text);
    node.type = "button";
    node.addEventListener("click", handler);
    return node;
  }
  function select(options, value, onChange, className = "") {
    const node = el("select", className);
    for (const [key, label] of options) {
      const option = el("option", "", label);
      option.value = key;
      option.selected = key === value;
      node.append(option);
    }
    node.addEventListener("change", () => onChange(node.value));
    return node;
  }
  function status(message, mode = "") {
    $("status-message").textContent = message;
    $("status-dot").className = "status-dot" + (mode ? " " + mode : "");
  }
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: "no-store", ...options });
    if (response.status === 204) return null;
    let payload;
    try { payload = await response.json(); }
    catch { throw new Error("サーバー応答を読み取れません"); }
    if (!response.ok) {
      const detail = Array.isArray(payload.detail)
        ? payload.detail.map(item => item.msg).join("; ") : payload.detail;
      throw new Error(typeof detail === "string" ? detail : "処理に失敗しました");
    }
    return payload;
  }
  function normalizeView(value) {
    const result = defaultView();
    if (value && Array.isArray(value.groups)) {
      result.groups = value.groups.filter(Array.isArray).slice(0, 8)
        .map(group => group.slice(0, 8));
    }
    if (value && typeof value.raw === "string") result.raw = value.raw.slice(0, 2048);
    if (value && [0, 1, 3, 5, 10].includes(Number(value.context))) {
      result.context = Number(value.context);
    }
    return result;
  }
  function normalizePins(value) {
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    return value.filter(item => item && Number.isInteger(item.number)
      && !seen.has(item.number) && seen.add(item.number)).slice(0, 50);
  }
  function viewKey() { return storage.viewPrefix + (state.active?.id || "none"); }
  function pinsKey() { return storage.pinsPrefix + (state.active?.id || "none"); }
  function persistView() {
    if (!state.active) return;
    try { localStorage.setItem(viewKey(), JSON.stringify(state.view)); } catch {}
  }
  function persistPins() {
    if (!state.active) return;
    try { localStorage.setItem(pinsKey(), JSON.stringify(state.pins)); } catch {}
  }
  function hasFilters() {
    return Boolean(state.view.raw.trim()
      || state.view.groups.some(group => group.length));
  }
  function filterCount() {
    return state.view.groups.reduce((sum, group) => sum + group.length, 0)
      + (state.view.raw.trim() ? 1 : 0);
  }

  Object.assign(A, {
    $, storage, columns, stringOperators, numberOperators, nativeOperators,
    operatorLabels, defaultView, parseStored, clone, state,
    el, button, select, status, formatSize, api, normalizeView, normalizePins,
    viewKey, pinsKey, persistView, persistPins, hasFilters, filterCount,
    ROW_HEIGHT: 30, OVERSCAN: 12, MAX_COMPARE_FIELDS: 320,
  });
})();
