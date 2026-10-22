/* Exceptional-save boundary: no cleanup before an atomic browser commit succeeds. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
(async () => {
  const events = [];
  let attempts = 0;
  const context = {self: {}, AbortController, setTimeout, clearTimeout, File,
    fetch: async () => ({ok: true, blob: async () => new Blob([new Uint8Array([10,13,13,10])])})};
  vm.runInNewContext(fs.readFileSync('static/app/live.worker.js', 'utf8'), context);
  const live = context.self.createLiveCapture({
    random: () => 'a'.repeat(64),
    remote: async (url, opts) => {events.push(url); return url.endsWith('/sessions') ? {id: 'b'.repeat(32), state: 'recording'} : {state: 'complete'};},
    store: async file => {assert.match(file.name, /\.pcapng$/); if (++attempts === 1) throw new Error('QuotaExceededError'); return {id: 'local', size: file.size};},
    cleanup: async () => {events.push('delete');},
  });
  await live.call('start', {interface: 'lo'}, () => {});
  await assert.rejects(live.call('save', {}, () => {}), /QuotaExceededError/);
  assert(!events.includes('delete'));
  const stored = await live.call('save', {}, () => {});
  assert.equal(stored.id, 'local');
  assert.equal(events.filter(v => v === 'delete').length, 1);
  assert.equal(attempts, 2);
  console.log('Capture local-save transaction contract passed');
})().catch(error => {console.error(error); process.exit(1);});
