/* Context menus and selected-text filtering for columns and protocol fields. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, columns, el, button, hasFilters } = A;
  A.filters = A.filters || {};

  function showPacketMenu(packet, field, cell, x, y) {
    const value = String(packet[field] ?? "");
    const meta = columns[field] || { label: field, type: "string" };
    const selected = selectedTextInside(cell.querySelector(".value-text") || cell);
    const items = [{ heading: `${meta.label} · ${selected || value}` }];
    const exact = {scope: "column", field, operator: "equals", value, kind: meta.type, case_sensitive: false};
    items.push(
      { label: "この値だけ表示", run: () => A.filters.addRule(exact, "replace") },
      { label: "この値を除外", run: () => A.filters.addRule({ ...exact, operator: "not_equals" }, "and") },
      { label: "ANDで追加", run: () => A.filters.addRule(exact, "and") },
      { label: "ORで追加", run: () => A.filters.addRule(exact, "or") },
    );
    if (meta.type === "string") {
      const part = selected || value;
      items.push({ divider: true },
        { label: selected ? "選択部分を含む" : "この文字列を含む",
          run: () => A.filters.addRule({ ...exact, operator: "contains", value: part }, "replace") },
        { label: selected ? "選択部分を含まない" : "この文字列を含まない",
          run: () => A.filters.addRule({ ...exact, operator: "not_contains", value: part }, "and") });
    }
    appendSelectedTextActions(items, exact, selected);
    items.push({divider: true}, {label: "送受信の階層を解析", run: () => A.relations.open(packet.number)});
    items.push({ divider: true }, {
      label: A.pins.isPinned(packet.number) ? "ピンを解除" : "このレコードをピン留め",
      run: () => A.pins.togglePin(packet),
    });
    if (state.pins.length >= 2) items.push({ label: "ピン留めしたレコードを比較", run: A.pins.openCompare });
    if (hasFilters()) {
      items.push({ divider: true }, { heading: "一致レコードの前後を透過表示" });
      for (const radius of [0, 1, 3, 5, 10]) {
        items.push({label: radius ? `前後${radius}件` : "前後表示を解除", run: () => A.filters.setContext(radius)});
      }
    }
    items.push({ divider: true },
      { label: "値をコピー", run: () => copyText(selected || value) },
      { label: "フィルター設定を開く", run: () => A.filters.toggleFilter(true) });
    showMenu(items, x, y);
  }
  function showDetailMenu(field, value, element, x, y, metadata = null) {
    const kind = metadata?.kind || inferKind(field, value);
    const selected = selectedTextInside(element.querySelector(".detail-value") || element);
    const exact = {scope: "wireshark", field, operator: "equals", value, kind, case_sensitive: false};
    const items = [{ heading: `${field} · ${selected || value}` },
      { label: "この値だけ表示", run: () => A.filters.addRule(exact, "replace") },
      { label: "この値を除外", run: () => A.filters.addRule({ ...exact, operator: "not_equals" }, "and") },
      { label: "ANDで追加", run: () => A.filters.addRule(exact, "and") },
      { label: "ORで追加", run: () => A.filters.addRule(exact, "or") }];
    if (kind === "string") {
      const part = selected || value;
      items.push({ divider: true },
        { label: "選択文字列を含む", run: () => A.filters.addRule({ ...exact, operator: "contains", value: part }, "replace") },
        { label: "選択文字列を含まない", run: () => A.filters.addRule({ ...exact, operator: "not_contains", value: part }, "and") });
    }
    appendSelectedTextActions(items, exact, selected);
    items.push({ divider: true },
      { label: "値をコピー", run: () => A.clipboard.copy(value) },
      { label: "表示値をコピー", run: () => A.clipboard.copy(metadata?.display_value || element.textContent) });
    if (metadata?.raw_value) items.push({label: "生値（16進）をコピー", run: () => A.clipboard.copy(metadata.raw_value)});
    showMenu(items, x, y);
  }
  function appendSelectedTextActions(items, exact, selected) {
    if (!selected || exact.kind !== "string") return;
    const contains = {...exact, operator: "contains", value: selected};
    items.push(
      {label: "選択部分を含む条件をANDで追加", run: () => A.filters.addRule(contains, "and")},
      {label: "選択部分を含む条件をORで追加", run: () => A.filters.addRule(contains, "or")},
    );
  }
  function inferKind(field, value) {
    const text = String(value ?? "");
    if (/^(?:ip|ipv6|eth)\.(?:src|dst|addr)/.test(field) && /^[0-9a-fA-F:.]+$/.test(text)) return "address";
    if (/^-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)$/.test(text)) return "number";
    return "string";
  }
  function showMenu(items, x, y) {
    const menu = $("context-menu");
    state.menuReturnFocus = document.activeElement;
    menu.replaceChildren();
    for (const item of items) {
      if (item.heading) { menu.append(el("div", "menu-heading", item.heading)); continue; }
      if (item.divider) { menu.append(el("div", "menu-divider")); continue; }
      const control = button(item.label, () => { hideMenu(); item.run(); }, "menu-action");
      control.setAttribute("role", "menuitem");
      menu.append(control);
    }
    placePopup(menu, x, y);
    menu.querySelector("button")?.focus({ preventScroll: true });
    menu.onkeydown = event => {
      const controls = Array.from(menu.querySelectorAll("button"));
      const index = controls.indexOf(document.activeElement);
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const step = event.key === "ArrowDown" ? 1 : -1;
        controls[(index + step + controls.length) % controls.length]?.focus();
      }
      if (event.key === "Tab") hideMenu();
    };
  }
  function hideMenu(restore = false) {
    const menu = $("context-menu");
    if (menu.hidden) return;
    menu.hidden = true;
    menu.replaceChildren();
    if (restore && state.menuReturnFocus?.isConnected) state.menuReturnFocus.focus();
  }
  function placePopup(node, x, y) {
    node.hidden = false;
    node.style.left = "0px";
    node.style.top = "0px";
    const rect = node.getBoundingClientRect();
    node.style.left = Math.max(5, Math.min(x, window.innerWidth - rect.width - 7)) + "px";
    node.style.top = Math.max(5, Math.min(y, window.innerHeight - rect.height - 7)) + "px";
  }
  function selectedTextInside(element) {
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed || !selection.rangeCount
        || !element.contains(selection.anchorNode) || !element.contains(selection.focusNode)) return "";
    return selection.toString().trim();
  }
  async function copyText(value) { return A.clipboard.copy(value); }

  Object.assign(A.filters, {
    showPacketMenu, showDetailMenu, inferKind, showMenu, hideMenu,
  });
})();
