/* Capture ownership stays in the storage worker. Commit locally before deleting remotely. */
'use strict';
self.createLiveCapture = ({remote, store, random, cleanup}) => {
  const catalogToken = random(32);
  let slot = null;
  const headers = item => ({Authorization: 'Bearer ' + item.token});
  async function request(url, options = {}, binary = false) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), binary ? 120000 : 20000);
    try {
      if (!binary) return await remote(url, {...options, signal: controller.signal});
      const response = await fetch(url, {credentials: 'omit', cache: 'no-store', ...options, signal: controller.signal});
      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.detail || '取得データを受信できません');
      }
      return await response.blob();
    } finally {clearTimeout(timer);}
  }
  const base = item => '/api/live/sessions/' + item.id;
  async function discard(bestEffort = false) {
    const current = slot;
    if (!current) return;
    if (current.starting) await current.starting.catch(() => {});
    if (!current.id && !bestEffort) {
      // Resolve an uncertain start response using the same idempotency capability.
      await start(current.options);
    }
    if (current.id) {
      try {await request(base(current) + '/stop', {method: 'POST', headers: headers(current)});}
      catch (error) {if (!bestEffort && error.status !== 404) throw error;}
      await cleanup(base(current), current);
    }
    current.closed = true;
    if (slot === current) slot = null;
  }
  async function start(args) {
    if (!slot) slot = {token: random(32), id: null, options: args, closed: false, starting: null, saving: null, record: null};
    const current = slot;
    if (JSON.stringify(current.options) !== JSON.stringify(args)) throw new Error('前の取得を保存または破棄してください');
    if (!current.starting) current.starting = request('/api/live/sessions', {
      method: 'POST', headers: {...headers(current), 'Content-Type': 'application/json'}, body: JSON.stringify(args),
    }).then(async result => {
      current.id = result.id;
      if (current.closed) {await cleanup(base(current), current); throw new Error('取得を終了しました');}
      return result;
    }).catch(error => {
      if (error.status >= 400 && error.status < 500 && slot === current) slot = null;
      throw error;
    }).finally(() => {current.starting = null;});
    return await current.starting;
  }
  async function save(report) {
    const current = slot;
    if (!current || current.closed) throw new Error('保存する取得セッションがありません');
    if (!current.id) await start(current.options);
    if (current.saving) return current.saving;
    current.saving = (async () => {
      if (!current.record) {
        report('capture_stop');
        const result = await request(base(current) + '/stop', {method: 'POST', headers: headers(current)});
        if (result.state !== 'complete') throw new Error(result.error || '取得を停止できません');
        report('capture_download');
        const blob = await request(base(current) + '/data', {headers: headers(current)}, true);
        const name = 'capture-' + current.options.interface.replace(/[^a-zA-Z0-9_.-]/g, '_') + '-' +
          new Date().toISOString().replace(/[:.]/g, '-') + '.pcapng';
        current.record = await store(new File([blob], name, {type: 'application/octet-stream'}), report);
      }
      // A failed local transaction throws above, retaining the remote session for retry.
      await cleanup(base(current), current);
      if (slot === current) slot = null;
      return current.record;
    })();
    try {return await current.saving;}
    finally {current.saving = null;}
  }
  return {
    close: () => discard(true),
    call: async (method, args, report) => {
      if (method === 'config') return request('/api/live/config', {headers: {Authorization: 'Bearer ' + catalogToken}});
      if (method === 'start') return start(args);
      if (method === 'status') {
        if (!slot) throw new Error('取得セッションがありません');
        if (!slot.id) return start(slot.options);
        return request(base(slot), {headers: headers(slot)});
      }
      if (method === 'save') return save(report);
      if (method === 'discard') return discard();
      throw new Error('未対応のキャプチャ操作です');
    },
  };
};
