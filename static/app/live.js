/* Focused capture setup; recording may continue while the existing viewer is used. */
(() => {
  'use strict';
  const A = window.PacketApp, {$} = A;
  let active = false, busy = false, timer = null, config = null, opener = null, savedOptions = null;
  let activity = 'idle';
  const dialog = $('live-dialog');
  const messages = {capture_stop: '取得を停止中…', capture_download: '取得データを受信中…',
    validating: '取得データを確認中…', saving: 'ブラウザに保存中…'};
  function message(text, error = false) {
    $('live-status').textContent = text;
    $('live-status').classList.toggle('is-error', error);
    $('live-status').setAttribute('role', error ? 'alert' : 'status');
  }
  function controls() {
    $('live-options').disabled = active || busy || !config?.enabled || !config.interfaces.length;
    $('live-start').hidden = active;
    $('live-start').disabled = busy || !config?.enabled || !config.interfaces.length;
    $('live-save').hidden = !active;
    $('live-save').disabled = busy || activity === 'failed';
    $('live-discard').hidden = !active;
    $('live-discard').disabled = busy;
    $('live-reload').hidden = active;
    $('live-reload').disabled = busy;
    $('live-status').classList.toggle('is-busy', busy);
    $('open-live').classList.toggle('is-recording', active);
    const labels = {starting: '取得開始中', recording: 'キャプチャ中', complete: '保存待ち',
      pending: '保存待ち', failed: '取得エラー', unknown: '取得確認', saving: '保存中'};
    $('open-live').textContent = active || (busy && activity !== 'idle') ? labels[activity] || '取得確認' : 'キャプチャ';
    $('open-live').setAttribute('aria-expanded', String(dialog.open));
  }
  async function configure() {
    if (active || busy) return;
    busy = true; controls(); message('インターフェースを取得中…');
    try {
      config = await A.local.live('config');
      const select = $('live-interface'); select.replaceChildren();
      for (const item of config.interfaces) {
        const option = document.createElement('option'); option.value = item.name; option.textContent = item.label; select.append(option);
      }
      message(config.enabled ? (config.interfaces.length ? '' : '利用可能なインターフェースがありません') : config.reason, !config.enabled);
    } catch (error) {config = null; message(error.message, true);}
    finally {busy = false; controls();}
  }
  let stylesReady = null;
  async function show() {
    if (!stylesReady) stylesReady = new Promise((resolve, reject) => {
      const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = '/static/live.css';
      link.onload = resolve;
      link.onerror = () => {link.remove(); stylesReady = null; reject(new Error('キャプチャ画面を読み込めません'));};
      document.head.append(link);
    });
    try {await stylesReady;} catch (error) {A.status(error.message, 'error'); return;}
    if (!dialog.open) {opener = document.activeElement; dialog.showModal();}
    controls(); if (!active && !busy) void configure();
  }
  function schedule() {clearTimeout(timer); if (active && !busy) timer = setTimeout(poll, 1000);}
  async function poll() {
    if (!active || busy) return;
    try {
      const result = await A.local.live('status');
      if (!active || busy) return;
      activity = result.state; controls();
      if (result.state === 'complete') {await finish(); return;}
      if (result.state === 'failed') {message(result.error, true); A.status('キャプチャに失敗しました', 'error'); return;}
      message(`${result.state === 'starting' ? '取得を開始中' : '取得中'} · ${result.interface} · ${A.formatSize(result.bytes)}`);
    } catch (error) {activity = 'unknown'; controls(); message(error.message, true);}
    schedule();
  }
  function readOptions() {
    return {interface: $('live-interface').value, protocol: $('live-protocol').value,
      host: $('live-host').value.trim(), direction: $('live-direction').value,
      port: $('live-port').value ? Number($('live-port').value) : null,
      duration: Number($('live-duration').value), size_mib: Number($('live-size').value),
      packets: Number($('live-packets').value), snaplen: Number($('live-snaplen').value), bpf: $('live-bpf').value.trim()};
  }
  async function start(event) {
    event.preventDefault(); if (busy || active || !$('live-form').reportValidity()) return;
    savedOptions = readOptions(); activity = 'starting'; busy = true; controls(); message('取得を開始中…');
    try {
      const result = await A.local.live('start', savedOptions);
      active = true; activity = result.state;
      message(result.state === 'failed' ? result.error : `${result.state === 'starting' ? '取得を開始中' : '取得中'} · ${result.interface}`, result.state === 'failed');
    } catch (error) {
      // The response may be lost after dumpcap starts. Keep stop/discard reachable.
      active = !(error.status >= 400 && error.status < 500); activity = active ? 'unknown' : 'idle'; message(error.message, true);
    } finally {busy = false; controls(); schedule();}
  }
  async function finish() {
    if (!active || busy) return;
    clearTimeout(timer); activity = 'saving'; busy = true; controls(); message('取得を停止中…');
    try {
      const record = await A.local.live('save', {}, phase => message(messages[phase] || '保存中…'));
      active = false; activity = 'idle'; savedOptions = null; $('live-save').textContent = '停止して保存';
      message('ブラウザに保存しました'); dialog.close();
      A.viewer.resetPacketView();
      localStorage.setItem(A.storage.current, record.id);
      await A.viewer.loadCaptures();
      if (!$('status-dot').classList.contains('error')) A.status(record.filename + ' · ローカル保存済み');
    } catch (error) {
      activity = 'pending';
      message(error.message, true); A.status('取得データの保存に失敗しました。キャプチャ画面から再試行してください', 'error');
      $('live-save').textContent = '保存を再試行';
      // Do not discard or repeatedly retry a failed IndexedDB write.
    } finally {busy = false; controls();}
  }
  async function discard() {
    if (!active || busy || !confirm('取得データを保存せずに破棄しますか？')) return;
    clearTimeout(timer); busy = true; controls(); message('取得を終了中…');
    try {await A.local.live('discard'); active = false; activity = 'idle'; savedOptions = null; message('取得データを破棄しました'); A.status('取得データを破棄しました');}
    catch (error) {message(error.message, true);}
    finally {busy = false; $('live-save').textContent = '停止して保存'; controls();}
  }
  $('open-live').addEventListener('click', show);
  $('live-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('keydown', event => {if (event.key === 'Escape') event.stopPropagation();});
  dialog.addEventListener('close', () => {controls(); opener?.focus({preventScroll: true});});
  $('live-form').addEventListener('submit', start);
  $('live-reload').addEventListener('click', configure);
  $('live-save').addEventListener('click', finish);
  $('live-discard').addEventListener('click', discard);
  window.addEventListener('beforeunload', event => {if (active) {event.preventDefault(); event.returnValue = '';}});
  controls();
})();
