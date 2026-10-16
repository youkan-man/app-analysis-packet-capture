/* Pane-local loading ownership. Old/cancelled work cannot finish a newer view. */
(() => {
  'use strict';
  const A = window.PacketApp;
  const scopes = {
    library: ['#capture-list'], packets: ['#packet-scroll'],
    detail: ['#packet-details', '.byte-viewport'],
    compare: ['.compare-scroll'], relations: ['#relations-content'],
  };
  const phases = {
    validating: 'ファイルを確認中…', saving: 'ブラウザに保存中…',
    reading: 'ローカルファイルを読み込み中…', uploading: '解析データを送信中…',
    submitting: '解析を要求中…', queued: '解析の開始待ち…', reconnecting: '解析に再接続中…',
  };
  const active = new Map(), surfaces = new Map();
  let ticker = null;
  function surface(selector, scope) {
    const target = document.querySelector(selector);
    if (!target) return null;
    if (surfaces.has(target)) return surfaces.get(target);
    const wrapper = A.el('div', 'loading-surface');
    wrapper.dataset.loadingScope = scope;
    target.before(wrapper); wrapper.append(target);
    const mask = A.el('div', 'loading-mask'); mask.hidden = true;
    const spinner = A.el('span', 'loading-spinner'); spinner.setAttribute('aria-hidden', 'true');
    const message = A.el('span', 'loading-message');
    message.setAttribute('role', 'status'); message.setAttribute('aria-live', 'polite');
    const context = A.el('span', 'loading-context');
    const elapsed = A.el('span', 'loading-elapsed'); elapsed.setAttribute('aria-hidden', 'true');
    mask.append(spinner, message, context, elapsed); wrapper.append(mask);
    const view = {target, wrapper, mask, message, context, elapsed};
    surfaces.set(target, view); return view;
  }
  function summary() {
    const pending = [...active.values()].filter(task => !task.failed);
    document.body.classList.toggle('has-pending', pending.length > 0);
    let node = document.getElementById('loading-summary');
    if (!node) {
      node = A.el('span'); node.id = 'loading-summary';
      document.getElementById('status-message').before(node);
    }
    node.hidden = !pending.length;
    node.textContent = pending.at(-1)?.message || '';
    if (pending.length && !ticker) ticker = setInterval(() => {
      for (const task of active.values()) if (!task.failed) {
        const seconds = Math.floor((performance.now() - task.started) / 1000);
        task.views.forEach(view => {view.elapsed.textContent = seconds ? `経過 ${seconds}秒` : '';});
      }
    }, 1000);
    if (!pending.length && ticker) {clearInterval(ticker); ticker = null;}
  }
  function hide(task) {
    task.views.forEach(view => {
      view.target.inert = false; view.target.setAttribute('aria-busy', 'false');
      view.mask.hidden = true; delete view.wrapper.dataset.loadingState;
    });
  }
  function clear(...names) {
    for (const name of names) {
      const task = active.get(name);
      if (task) {hide(task); active.delete(name);}
    }
    summary();
  }
  function begin(scope, label, context = '') {
    const views = scopes[scope].map(selector => surface(selector, scope)).filter(Boolean);
    const task = {views, label, message: label, started: performance.now(), failed: false};
    active.set(scope, task);
    const current = () => active.get(scope) === task;
    function paint() {
      views.forEach(view => {
        view.target.inert = true; view.target.setAttribute('aria-busy', String(!task.failed));
        view.wrapper.dataset.loadingState = task.failed ? 'error' : 'busy';
        view.message.setAttribute('role', task.failed ? 'alert' : 'status');
        view.message.textContent = task.message;
        view.context.textContent = context; view.context.hidden = !context;
        view.elapsed.textContent = ''; view.mask.hidden = false;
      });
      summary();
    }
    paint();
    return {
      progress: phase => {
        if (!current() || task.failed) return;
        task.message = phases[phase] || label;
        views.forEach(view => {view.message.textContent = task.message;}); summary();
      },
      fail: message => {if (current()) {task.failed = true; task.message = message; paint();}},
      end: () => {if (current() && !task.failed) {hide(task); active.delete(scope); summary();}},
    };
  }
  A.loading = {begin, clear};
})();
