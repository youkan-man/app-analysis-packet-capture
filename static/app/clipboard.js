/* Plain-text clipboard boundary; never copy rendered offsets or neighbouring columns. */
(() => {
  'use strict';
  const A = window.PacketApp;
  async function copy(text) {
    const value = String(text ?? '');
    try {
      if (window.isSecureContext && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const previous = document.activeElement;
        const input = document.createElement('textarea');
        input.value = value;
        input.style.cssText = 'position:fixed;top:0;left:-10000px';
        document.body.append(input);
        input.select();
        const success = document.execCommand('copy');
        input.remove(); previous?.focus({preventScroll: true});
        if (!success) throw new Error('Clipboard unavailable');
      }
      A.status('コピーしました');
      return true;
    } catch {
      A.status('クリップボードに書き込めません。ブラウザの権限を確認してください', 'error');
      return false;
    }
  }
  A.clipboard = {copy};
})();
