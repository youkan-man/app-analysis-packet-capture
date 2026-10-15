/* Info-column search, text selection, and context actions.
 * This UI owns only Info predicates/menu state. The app owns capture and Wireshark state.
 */
(() => {
  "use strict";

  const $ = id => document.getElementById(id);
  const OPERATORS = Object.freeze({
    contains: "含む",
    not_contains: "含まない",
    equals: "完全一致",
    not_equals: "一致しない",
    starts_with: "先頭一致",
    ends_with: "末尾一致",
  });
  const MAX_TEXT = 200;

  function element(tag, className = "", text = "") {
    const item = document.createElement(tag);
    if (className) item.className = className;
    item.textContent = text;
    return item;
  }
  function action(label, handler, className = "") {
    const control = element("button", className, label);
    control.type = "button";
    control.addEventListener("click", handler);
    return control;
  }
  function selectedInside(element) {
    const selected = window.getSelection();
    if (!selected || selected.isCollapsed || !selected.rangeCount) return "";
    if (!element.contains(selected.anchorNode) || !element.contains(selected.focusNode)) return "";
    return selected.toString().trim();
  }
  function fitPopup(popup, x, y) {
    popup.hidden = false;
    popup.style.left = "0px";
    popup.style.top = "0px";
    const rect = popup.getBoundingClientRect();
    popup.style.left = Math.max(5, Math.min(x, window.innerWidth - rect.width - 7)) + "px";
    popup.style.top = Math.max(5, Math.min(y, window.innerHeight - rect.height - 7)) + "px";
  }
  function displayLiteral(field, value) {
    const text = String(value || "").trim();
    if (!text) return null;
    if (/^(?:ip|ipv6|eth)\.(?:src|dst)$/.test(field) && /^[0-9a-fA-F:.]+$/.test(text)) return text;
    if (/^-?(?:\d+(?:\.\d+)?|0x[0-9a-fA-F]+)$/.test(text)) return text;
    return JSON.stringify(text);
  }
  function displayCandidate(packet, column) {
    const fields = packet.fields || {};
    if (column === 0) return { field: "frame.number", value: String(packet.number) };
    if (column === 1) return { field: "frame.time_relative", value: String(packet.time) };
    if (column === 5) return { field: "frame.len", value: String(packet.length) };
    if (column === 2 || column === 3) {
      const side = column === 2 ? "src" : "dst";
      const field = ["ip." + side, "ipv6." + side, "eth." + side].find(name => fields[name]);
      return field ? { field, value: fields[field] } : null;
    }
    if (column === 4) {
      const name = String(packet.protocol || "").toLowerCase().trim();
      const protocol = name.startsWith("tls") ? "tls" : name.replace(/[^a-z0-9_.]/g, "");
      return /^[a-z_][a-z0-9_.]*$/.test(protocol) ? { field: protocol, value: null } : null;
    }
    return null;
  }
  function validGroups(groups) {
    if (!Array.isArray(groups) || groups.length > 8) return false;
    let total = 0;
    for (const group of groups) {
      if (!Array.isArray(group) || group.length < 1 || group.length > 8) return false;
      total += group.length;
      for (const rule of group) {
        if (!rule || !Object.hasOwn(OPERATORS, rule.operator) ||
            typeof rule.value !== "string" || !rule.value.trim() ||
            rule.value.length > MAX_TEXT || typeof rule.case_sensitive !== "boolean") return false;
      }
    }
    return total <= 32 && JSON.stringify({ groups }).length <= 4096;
  }

  class PacketInfoControls {
    constructor({ onInfoChange, onDisplayChange, onStatus }) {
      this.groups = [];
      this.onInfoChange = onInfoChange;
      this.onDisplayChange = onDisplayChange;
      this.onStatus = onStatus;
      this.menu = $("packet-context-menu");
      this.toolbar = $("selection-tools");
      this.menuReturnFocus = null;
      this.selectedInfo = "";
      this.selectedCell = null;

      $("info-form").addEventListener("submit", event => {
        event.preventDefault();
        const text = $("info-query").value;
        this.update(text, $("info-mode").value, $("info-join").value, $("info-case").checked);
      });
      $("info-clear").addEventListener("click", () => this.setGroups([]));
      for (const btn of this.toolbar.querySelectorAll("[data-info-action]")) {
        btn.addEventListener("click", () => {
          const operator = btn.dataset.operator || "contains";
          this.update(this.selectedInfo, operator, btn.dataset.infoAction);
        });
      }
      $("selection-more").addEventListener("click", () => {
        if (!this.selectedCell || !this.selectedInfo) return;
        const rect = this.toolbar.getBoundingClientRect();
        this.showInfoMenu(this.selectedInfo, rect.left, rect.bottom + 4);
      });

      document.addEventListener("pointerdown", event => {
        if (!this.menu.hidden && !this.menu.contains(event.target)) this.hideMenu();
        if (!this.toolbar.hidden && !this.toolbar.contains(event.target)
            && !event.target.closest(".info-cell")) this.hideToolbar();
      });
      document.addEventListener("keydown", event => {
        if (event.key === "Escape") {
          if (!this.menu.hidden) {
            event.preventDefault();
            this.hideMenu(true);
          } else if (!this.toolbar.hidden) this.hideToolbar();
        }
      });
      window.addEventListener("resize", () => { this.hideMenu(); this.hideToolbar(); });
      document.addEventListener("scroll", event => {
        if (event.target?.closest?.(".packet-scroll")) this.hideToolbar();
      }, true);
      this.renderChips();
    }

    getGroups() {
      return this.groups.map(group => group.map(rule => ({ ...rule })));
    }
    getQuery() {
      return this.groups.length ? JSON.stringify({ groups: this.groups }) : "";
    }
    setGroups(groups) {
      let cloned;
      try { cloned = JSON.parse(JSON.stringify(groups)); } catch { cloned = null; }
      if (!validGroups(cloned)) {
        this.onStatus("Info条件は8グループ・合計32件・1項目200文字以内にしてください", "error");
        return false;
      }
      this.groups = cloned;
      this.hideMenu();
      this.hideToolbar();
      this.renderChips();
      this.onInfoChange();
      return true;
    }
    update(rawText, operator = "contains", join = "replace", caseSensitive) {
      const value = String(rawText || "").trim();
      if (!value || value.length > MAX_TEXT || !Object.hasOwn(OPERATORS, operator)) {
        this.onStatus("Infoの検索文字列は1〜200文字で指定してください", "error");
        return false;
      }
      const rule = { operator, value, case_sensitive:
        typeof caseSensitive === "boolean" ? caseSensitive : $("info-case").checked };
      let next;
      if (join === "and" && this.groups.length) {
        next = this.groups.map(group => [...group, rule]);
      } else if (join === "or" && this.groups.length) {
        next = [...this.getGroups(), [rule]];
      } else {
        next = [[rule]];
      }
      const accepted = this.setGroups(next);
      if (accepted) {
        $("info-query").value = value;
        $("info-mode").value = operator;
      }
      return accepted;
    }
    renderChips() {
      const container = $("info-chips");
      container.replaceChildren();
      container.hidden = !this.groups.length;
      $("info-clear").disabled = !this.groups.length;
      this.groups.forEach((group, groupIndex) => {
        if (groupIndex) container.append(element("span", "info-group-join", "OR"));
        const groupBox = element("div", "info-group");
        group.forEach((rule, index) => {
          if (index) groupBox.append(element("span", "info-clause-join", "AND"));
          const chip = element("div", "info-chip");
          chip.title = rule.value;
          chip.append(element("span", "", OPERATORS[rule.operator] +
            (rule.case_sensitive ? " Aa" : "") + ": " + rule.value));
          const remove = action("×", () => {
            const next = this.getGroups();
            next[groupIndex].splice(index, 1);
            if (!next[groupIndex].length) next.splice(groupIndex, 1);
            this.setGroups(next);
          }, "info-chip-remove");
          remove.setAttribute("aria-label", "Info条件を削除: " + rule.value);
          chip.append(remove);
          groupBox.append(chip);
        });
        container.append(groupBox);
      });
    }
    decorateInfoCell(cell, packet) {
      cell.classList.add("info-cell");
      const text = element("span", "info-text", String(packet.info ?? ""));
      const more = action("⋯", event => {
        event.stopPropagation();
        const rect = more.getBoundingClientRect();
        this.showPacketMenu(packet, 6, cell, rect.left, rect.bottom + 3);
      }, "packet-row-actions");
      more.setAttribute("aria-label", "Info列のフィルター操作");
      more.title = "Infoでフィルター";
      cell.append(text, more);
      cell.addEventListener("mouseup", event => {
        if (event.button !== 0) return;
        const selection = selectedInside(text);
        if (!selection) return;
        this.selectedInfo = selection;
        this.selectedCell = cell;
        const rect = window.getSelection().getRangeAt(0).getBoundingClientRect();
        this.showToolbar(rect);
      });
    }
    attachPacketRow(row, packet) {
      row.addEventListener("contextmenu", event => {
        const cell = event.target.closest("td");
        if (!cell || !row.contains(cell)) return;
        event.preventDefault();
        this.showPacketMenu(packet, cell.cellIndex, cell, event.clientX, event.clientY);
      });
      row.addEventListener("keydown", event => {
        if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
          event.preventDefault();
          const target = row.cells[6] || row;
          const rect = target.getBoundingClientRect();
          this.showPacketMenu(packet, 6, target, rect.left + 24, rect.top + 16);
        }
      });
    }
    attachDetailField(line, key, value) {
      if (!/^[a-zA-Z_][a-zA-Z0-9_.]*(?:#[0-9]+)?$/.test(key)) return;
      line.classList.add("contextual-field");
      line.title = "右クリックでフィールドをフィルター";
      line.tabIndex = 0;
      line.addEventListener("contextmenu", event => {
        event.preventDefault();
        this.showFieldMenu(key, String(value ?? ""), event.clientX, event.clientY);
      });
      line.addEventListener("keydown", event => {
        if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
          event.preventDefault();
          const rect = line.getBoundingClientRect();
          this.showFieldMenu(key, String(value ?? ""), rect.left + 12, rect.bottom);
        }
      });
    }
    showToolbar(rect) {
      this.hideMenu();
      this.toolbar.hidden = false;
      $("selection-text").textContent = this.selectedInfo.length > 34
        ? this.selectedInfo.slice(0, 34) + "…" : this.selectedInfo;
      const top = rect.top > 58 ? rect.top - 44 : rect.bottom + 7;
      fitPopup(this.toolbar, rect.left, top);
    }
    hideToolbar() {
      this.toolbar.hidden = true;
      this.selectedCell = null;
    }
    hideMenu(restoreFocus = false) {
      if (this.menu.hidden) return;
      this.menu.hidden = true;
      this.menu.replaceChildren();
      if (restoreFocus && this.menuReturnFocus?.isConnected) this.menuReturnFocus.focus();
    }
    showMenu(items, x, y) {
      this.hideToolbar();
      this.menuReturnFocus = document.activeElement;
      this.menu.replaceChildren();
      for (const item of items) {
        if (item.heading) {
          this.menu.append(element("div", "context-heading", item.heading));
          continue;
        }
        if (item.divider) {
          this.menu.append(element("div", "context-divider"));
          continue;
        }
        this.menu.append(action(item.label, () => {
          this.hideMenu();
          item.run();
        }, "context-action"));
      }
      fitPopup(this.menu, x, y);
      const first = this.menu.querySelector("button");
      first?.focus({ preventScroll: true });
      this.menu.onkeydown = event => {
        const controls = Array.from(this.menu.querySelectorAll("button"));
        const index = controls.indexOf(document.activeElement);
        if (event.key === "ArrowDown" || event.key === "ArrowUp") {
          event.preventDefault();
          const step = event.key === "ArrowDown" ? 1 : -1;
          controls[(index + step + controls.length) % controls.length]?.focus();
        } else if (event.key === "Tab") {
          this.hideMenu();
        }
      };
    }
    showInfoMenu(value, x, y) {
      const short = value.length > 44 ? value.slice(0, 44) + "…" : value;
      this.showMenu([
        { heading: "Info · " + short },
        { label: "含む 〔この条件に置換〕", run: () => this.update(value, "contains", "replace") },
        { label: "含まない 〔この条件に置換〕", run: () => this.update(value, "not_contains", "replace") },
        { label: "完全一致で表示", run: () => this.update(value, "equals", "replace") },
        { divider: true },
        { label: "AND で含む条件を追加", run: () => this.update(value, "contains", "and") },
        { label: "OR で含む条件を追加", run: () => this.update(value, "contains", "or") },
        { label: "AND で除外を追加", run: () => this.update(value, "not_contains", "and") },
        { divider: true },
        { label: "文字列をコピー", run: () => this.copy(value) },
      ], x, y);
    }
    copy(value) {
      if (!navigator.clipboard?.writeText) {
        this.onStatus("この環境ではクリップボードにアクセスできません", "error");
        return;
      }
      navigator.clipboard.writeText(String(value)).then(() => {
        this.onStatus("コピーしました");
      }).catch(() => { this.onStatus("クリップボードに書き込めません", "error"); });
    }
    fieldActions(field, value, heading) {
      const rhs = value === null ? null : displayLiteral(field, value);
      if (value !== null && !rhs) return [];
      const expression = value === null ? field : field + " == " + rhs;
      return [
        { heading: heading || field },
        { label: "この値で表示", run: () => this.onDisplayChange(expression, "replace") },
        { label: "この値を除外", run: () => this.onDisplayChange("!(" + expression + ")", "and") },
        { label: "AND に追加", run: () => this.onDisplayChange(expression, "and") },
        { label: "OR に追加", run: () => this.onDisplayChange(expression, "or") },
        { label: "フィルター式をコピー", run: () => this.copy(expression) },
      ];
    }
    showFieldMenu(field, value, x, y) {
      const menu = this.fieldActions(field, value, field + " · " + value.slice(0, 42));
      if (menu.length) this.showMenu(menu, x, y);
    }
    showPacketMenu(packet, column, cell, x, y) {
      if (column === 6) {
        const selection = selectedInside(cell.querySelector(".info-text") || cell);
        this.showInfoMenu(selection || String(packet.info ?? ""), x, y);
        return;
      }
      const candidate = displayCandidate(packet, column);
      if (!candidate) {
        this.showInfoMenu(String(packet.info ?? ""), x, y);
        return;
      }
      const fields = packet.fields || {};
      const items = this.fieldActions(candidate.field, candidate.value,
        (["No.", "Time", "Source", "Destination", "Protocol", "Length"][column] || "フィールド") +
        " · " + candidate.field);
      const transport = fields["tcp.srcport"] ? "tcp" : (fields["udp.srcport"] ? "udp" : "");
      if (transport) {
        for (const side of ["srcport", "dstport"]) {
          const field = transport + "." + side;
          if (!fields[field]) continue;
          const expression = field + " == " + fields[field];
          items.push({ divider: true });
          items.push({ heading: (side === "srcport" ? "送信元ポート " : "宛先ポート ") + fields[field] });
          items.push({ label: "ポートで表示", run: () => this.onDisplayChange(expression, "replace") });
          items.push({ label: "ポートを AND に追加", run: () => this.onDisplayChange(expression, "and") });
        }
      }
      this.showMenu(items, x, y);
    }
  }

  window.PacketInfoControls = PacketInfoControls;
})();
