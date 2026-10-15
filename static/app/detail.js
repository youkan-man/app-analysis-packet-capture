/* Protocol hierarchy and hexadecimal byte rendering. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, el } = A;
  A.viewer = A.viewer || {};

  function clearDetail() {
    $("selected-number").textContent = "—";
    $("byte-count").textContent = "0 B";
    $("packet-details").replaceChildren(el("div", "empty-detail", "パケットを選択してください"));
    $("packet-bytes").replaceChildren();
  }
  function renderDetails(layers) {
    const container = $("packet-details");
    container.replaceChildren();
    let rendered = 0;
    const names = {
      frame: "Frame", eth: "Ethernet II", ip: "Internet Protocol Version 4",
      ipv6: "Internet Protocol Version 6", tcp: "Transmission Control Protocol",
      udp: "User Datagram Protocol", dns: "Domain Name System", tls: "Transport Layer Security",
    };
    function append(parent, key, value, depth) {
      if (++rendered > 900 || depth > 14 || key.endsWith("_raw")) return;
      if (value !== null && typeof value === "object") {
        const details = el("details");
        if (depth === 0 && key !== "frame") details.open = true;
        details.append(el("summary", "", (depth === 0 ? names[key] || key : key)
          + (Array.isArray(value) ? ` [${value.length}]` : "")));
        const entries = Array.isArray(value)
          ? value.map((item, index) => [String(index + 1), item]) : Object.entries(value);
        for (const [child, data] of entries) append(details, child, data, depth + 1);
        parent.append(details);
      } else {
        const line = el("div", "detail-leaf");
        line.tabIndex = 0;
        line.append(el("span", "detail-key", key + ": "),
          el("span", "detail-value value-text", String(value ?? "")));
        if (/^[A-Za-z_][A-Za-z0-9_.]*(?:#[0-9]+)?$/.test(key)) {
          line.dataset.scope = "wireshark";
          line.dataset.field = key;
          line.dataset.value = String(value ?? "");
          line.addEventListener("contextmenu", event => {
            event.preventDefault();
            A.filters.showDetailMenu(key, String(value ?? ""), line,
              event.clientX, event.clientY);
          });
          line.addEventListener("keydown", event => {
            if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
              event.preventDefault();
              const rect = line.getBoundingClientRect();
              A.filters.showDetailMenu(key, String(value ?? ""), line,
                rect.left + 12, rect.bottom);
            }
          });
          line.addEventListener("mouseup", event => A.filters.selectionFromElement(
            event, line.querySelector(".detail-value"),
            { scope: "wireshark", field: key, kind: A.filters.inferKind(key, value) }));
        }
        parent.append(line);
      }
    }
    for (const [key, value] of Object.entries(layers || {})) append(container, key, value, 0);
    if (!container.children.length) {
      container.append(el("div", "empty-detail", "プロトコル詳細はありません"));
    }
  }
  function renderHex(hex) {
    const container = $("packet-bytes");
    container.replaceChildren();
    if (!hex || !/^[a-fA-F0-9]+$/.test(hex)) {
      $("byte-count").textContent = "取得できません";
      return;
    }
    const bytes = hex.match(/.{2}/g) || [];
    $("byte-count").textContent = bytes.length + " B";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const row = el("div", "hex-row");
      row.append(el("span", "hex-offset", i.toString(16).padStart(4, "0")),
        el("span", "hex-digits", chunk.join(" ").padEnd(47, " ")),
        el("span", "hex-ascii", chunk.map(value => {
          const code = parseInt(value, 16);
          return code >= 32 && code <= 126 ? String.fromCharCode(code) : ".";
        }).join("")));
      container.append(row);
    }
  }

  Object.assign(A.viewer, { clearDetail, renderDetails, renderHex });
})();
