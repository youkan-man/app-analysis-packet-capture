/* Application event wiring and startup. */
(() => {
  "use strict";
  const A = window.PacketApp;
  const { $, state, status, api, defaultView } = A;

  async function uploadFiles(files) {
    for (const file of files) {
      if (!file) continue;
      status(file.name + " を取り込み中...", "busy");
      const form = new FormData();
      form.append("file", file);
      try {
        const capture = await api("/api/captures", { method: "POST", body: form });
        state.active = null;
        localStorage.setItem(A.storage.current, capture.id);
        await A.viewer.loadCaptures();
        status(file.name + " を取り込みました");
      } catch (error) { status(file.name + ": " + error.message, "error"); }
    }
    $("file-input").value = "";
  }
  function addEditableRule(groupIndex = 0) {
    if (!state.view.groups.length) state.view.groups.push([]);
    const group = state.view.groups[Math.min(groupIndex, state.view.groups.length - 1)];
    group.push({
      scope: "column", field: "protocol", operator: "equals",
      value: "", kind: "string", case_sensitive: false,
    });
    A.filters.renderFilterDrawer();
  }
  function wireEvents() {
    $("open-file").addEventListener("click", () => $("file-input").click());
    $("drop-target").addEventListener("click", () => $("file-input").click());
    $("file-input").addEventListener("change", event => uploadFiles(Array.from(event.target.files)));
    $("refresh").addEventListener("click", A.viewer.loadCaptures);
    $("toggle-filter").addEventListener("click", () => A.filters.toggleFilter());
    $("close-filter").addEventListener("click", () => A.filters.toggleFilter(false));
    $("add-condition").addEventListener("click", () => addEditableRule(0));
    $("add-group").addEventListener("click", () => {
      if (state.view.groups.length >= 8) return;
      state.view.groups.push([]);
      addEditableRule(state.view.groups.length - 1);
    });
    $("clear-filters").addEventListener("click", () => {
      state.view = defaultView();
      A.filters.commitView();
    });
    $("apply-filters").addEventListener("click", () => {
      state.view.raw = $("raw-filter").value.trim();
      state.view.context = Number($("context-radius").value);
      $("filter-error").textContent = "";
      A.filters.commitView({ keepSelection: true });
    });
    $("context-radius").addEventListener("change", () => {
      state.view.context = Number($("context-radius").value);
    });
    $("save-filter").addEventListener("click", A.filters.saveCurrentFilter);
    $("delete-filter").addEventListener("click", A.filters.deleteSavedFilter);
    $("saved-filters").addEventListener("change", event => {
      A.filters.loadSavedFilter(Number(event.target.value) - 1);
    });
    $("packet-scroll").addEventListener("scroll", () => {
      A.viewer.renderVirtualRows();
    });
    $("open-compare").addEventListener("click", A.pins.openCompare);
    $("compare-pins").addEventListener("click", A.pins.openCompare);
    $("close-compare").addEventListener("click", A.pins.closeCompare);
    $("clear-pins").addEventListener("click", A.pins.clearPins);
    $("diff-only").addEventListener("change", A.pins.renderComparison);
    document.addEventListener("pointerdown", event => {
      if (!$("context-menu").hidden && !$("context-menu").contains(event.target)) {
        A.filters.hideMenu();
      }
    });
    document.addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") {
        event.preventDefault();
        $("file-input").click();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        A.filters.toggleFilter(true);
      }
      if (event.key === "Escape") {
        if (!$("context-menu").hidden) A.filters.hideMenu(true);
        else if (!$("compare-panel").hidden) A.pins.closeCompare();
        else if (state.filterOpen) A.filters.toggleFilter(false);
      }
    });
    window.addEventListener("resize", () => {
      A.filters.hideMenu();
      A.viewer.renderVirtualRows(true);
    });
    let dragDepth = 0;
    document.addEventListener("dragenter", event => {
      if (!event.dataTransfer?.types.includes("Files")) return;
      event.preventDefault();
      dragDepth++;
      $("drag-overlay").hidden = false;
    });
    document.addEventListener("dragover", event => {
      if (event.dataTransfer?.types.includes("Files")) event.preventDefault();
    });
    document.addEventListener("dragleave", () => {
      if (--dragDepth <= 0) {
        dragDepth = 0;
        $("drag-overlay").hidden = true;
      }
    });
    document.addEventListener("drop", event => {
      event.preventDefault();
      dragDepth = 0;
      $("drag-overlay").hidden = true;
      if (event.dataTransfer?.files?.length) uploadFiles(Array.from(event.dataTransfer.files));
    });
  }

  wireEvents();
  A.filters.renderSavedFilters();
  A.filters.renderFilterDrawer();
  A.viewer.renderAll();
  A.viewer.loadCaptures();
})();
