/* Generic filter model, drawer editing, active chips, and saved views. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, columns, stringOperators, numberOperators, nativeOperators,
    operatorLabels, el, button, select, status, clone, storage, normalizeView,
    persistView, hasFilters } = A;
  A.filters = A.filters || {};

  function filterLabel(rule) {
    const field = rule.scope === "column"
      ? columns[rule.field]?.label || rule.field : rule.field;
    const operator = operatorLabels[rule.operator] || rule.operator;
    return `${field} ${operator}${rule.value ? ` ${rule.value}` : ""}`;
  }
  function renderActiveFilters() {
    const container = $("active-filters");
    container.replaceChildren();
    state.view.groups.forEach((group, groupIndex) => {
      if (groupIndex) container.append(el("span", "group-join", "OR"));
      group.forEach((rule, ruleIndex) => {
        if (ruleIndex) container.append(el("span", "clause-join", "AND"));
        const chip = el("div", "filter-chip");
        chip.title = filterLabel(rule);
        chip.append(el("span", "", filterLabel(rule)),
          button("×", () => removeRule(groupIndex, ruleIndex)));
        container.append(chip);
      });
    });
    if (state.view.raw.trim()) {
      if (state.view.groups.length) container.append(el("span", "clause-join", "AND"));
      const chip = el("div", "filter-chip");
      chip.title = state.view.raw;
      chip.append(el("span", "", "Wireshark: " + state.view.raw),
        button("×", () => { state.view.raw = ""; commitView(); }));
      container.append(chip);
    }
    if (hasFilters() && state.view.context) {
      const chip = el("div", "filter-chip");
      chip.append(el("span", "", `前後${state.view.context}件を透過`),
        button("×", () => setContext(0)));
      container.append(chip);
    }
    container.hidden = !container.children.length;
    A.viewer.renderCounts();
  }
  function removeRule(groupIndex, ruleIndex) {
    state.view.groups[groupIndex].splice(ruleIndex, 1);
    if (!state.view.groups[groupIndex].length) state.view.groups.splice(groupIndex, 1);
    commitView();
  }
  function addRule(rule, mode = "replace") {
    const normalized = normalizeRule(rule);
    if (!normalized) {
      status("フィルター値を確認してください", "error");
      return;
    }
    if (mode === "replace" || !state.view.groups.length) {
      state.view.groups = [[normalized]];
    } else if (mode === "or") {
      state.view.groups.push([normalized]);
    } else {
      state.view.groups = state.view.groups.map(group => [...group, normalized]);
    }
    commitView();
  }
  function normalizeRule(rule) {
    if (!rule || !rule.field || !rule.operator) return null;
    const result = {
      scope: rule.scope || "column",
      field: rule.field,
      operator: rule.operator,
      value: String(rule.value ?? ""),
      kind: rule.kind || (columns[rule.field]?.type || "string"),
      case_sensitive: Boolean(rule.case_sensitive),
    };
    if (!["exists", "not_exists"].includes(result.operator) && !result.value.length) {
      return null;
    }
    return result;
  }
  function commitView(options = {}) {
    persistView();
    renderFilterDrawer();
    renderActiveFilters();
    A.viewer.loadPackets({ keepSelection: options.keepSelection });
  }
  function setContext(radius) {
    state.view.context = Number(radius) || 0;
    $("context-radius").value = String(state.view.context);
    commitView({ keepSelection: true });
  }
  function renderFilterDrawer() {
    const container = $("filter-groups");
    container.replaceChildren();
    state.view.groups.forEach((group, groupIndex) => {
      const box = el("div", "filter-group");
      const head = el("div", "filter-group-head");
      head.append(el("span", "", groupIndex
        ? `ORグループ ${groupIndex + 1}` : "条件グループ 1"));
      head.append(button("グループ削除", () => {
        state.view.groups.splice(groupIndex, 1);
        renderFilterDrawer();
      }, "button button-quiet"));
      box.append(head);
      group.forEach((rule, ruleIndex) => {
        box.append(filterRuleEditor(rule, groupIndex, ruleIndex));
      });
      container.append(box);
    });
    if (!state.view.groups.length) {
      container.append(el("div", "empty-detail",
        "画面の値を右クリックするか、［＋ 条件］で追加します。"));
    }
    $("raw-filter").value = state.view.raw;
    $("context-radius").value = String(state.view.context);
    renderSavedFilters();
  }
  function filterRuleEditor(rule, groupIndex, ruleIndex) {
    const row = el("div", "filter-rule");
    if (rule.scope === "column") {
      const fields = Object.entries(columns).map(([key, meta]) => [key, meta.label]);
      row.append(select(fields, rule.field, value => {
        rule.field = value;
        rule.kind = columns[value].type;
        rule.operator = rule.kind === "number" ? "equals" : "contains";
        renderFilterDrawer();
      }));
    } else {
      const field = el("input");
      field.value = rule.field;
      field.readOnly = true;
      field.title = "プロトコル詳細から追加されたWiresharkフィールド";
      row.append(field);
    }
    const operators = rule.scope === "wireshark"
      ? nativeOperators
      : (columns[rule.field]?.type === "number" ? numberOperators : stringOperators);
    row.append(select(operators, rule.operator, value => {
      rule.operator = value;
      renderFilterDrawer();
    }));
    const value = el("input");
    value.value = rule.value || "";
    value.placeholder = "比較値";
    value.disabled = ["exists", "not_exists"].includes(rule.operator);
    value.addEventListener("input", () => { rule.value = value.value; });
    row.append(value);
    row.append(button("×", () => {
      state.view.groups[groupIndex].splice(ruleIndex, 1);
      if (!state.view.groups[groupIndex].length) state.view.groups.splice(groupIndex, 1);
      renderFilterDrawer();
    }));
    return row;
  }
  function toggleFilter(open) {
    state.filterOpen = typeof open === "boolean" ? open : !state.filterOpen;
    $("filter-drawer").hidden = !state.filterOpen;
    $("workspace").classList.toggle("filter-open", state.filterOpen);
    $("toggle-filter").setAttribute("aria-expanded", String(state.filterOpen));
    if (state.filterOpen) {
      renderFilterDrawer();
      $("add-condition").focus();
    } else {
      $("toggle-filter").focus();
    }
  }
  function renderSavedFilters() {
    const control = $("saved-filters");
    control.replaceChildren();
    const empty = el("option", "", "保存済み");
    empty.value = "";
    control.append(empty);
    state.saved.forEach((item, index) => {
      const option = el("option", "", item.name);
      option.value = String(index + 1);
      control.append(option);
    });
  }
  function saveCurrentFilter() {
    if (!hasFilters()) {
      status("保存する条件がありません", "error");
      return;
    }
    const name = prompt("フィルター名", "フィルター " + (state.saved.length + 1));
    if (name === null || !name.trim()) return;
    const item = { name: name.trim().slice(0, 60), view: clone(state.view) };
    state.saved = [item, ...state.saved.filter(value => value.name !== item.name)]
      .slice(0, 30);
    localStorage.setItem(storage.saved, JSON.stringify(state.saved));
    renderSavedFilters();
    status("フィルターを保存しました");
  }
  function loadSavedFilter(index) {
    const item = state.saved[index];
    if (!item) return;
    state.view = normalizeView(clone(item.view));
    commitView();
  }
  function deleteSavedFilter() {
    const index = Number($("saved-filters").value) - 1;
    if (index < 0) {
      status("削除する保存済みフィルターを選択してください", "error");
      return;
    }
    const [removed] = state.saved.splice(index, 1);
    localStorage.setItem(storage.saved, JSON.stringify(state.saved));
    renderSavedFilters();
    status((removed?.name || "フィルター") + "を削除しました");
  }

  Object.assign(A.filters, {
    filterLabel, renderActiveFilters, removeRule, addRule, normalizeRule,
    commitView, setContext, renderFilterDrawer, toggleFilter,
    renderSavedFilters, saveCurrentFilter, loadSavedFilter, deleteSavedFilter,
  });
})();
