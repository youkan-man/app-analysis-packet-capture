/* Initialize optional inspection surfaces before the existing application starts. */
(() => {
  'use strict';
  const A = window.PacketApp;
  A.inspector.init();
  A.relations.init();
  A.layout.init();
})();
