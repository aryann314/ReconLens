/* =========================================================================
   scan_detail.js - full-page view of one stored scan (/scan/<id>).
   ========================================================================= */
"use strict";

(async () => {
  const box = document.getElementById("results");
  const id = document.body.dataset.scanId;
  try {
    const data = await OSINT.api(`/api/scans/${encodeURIComponent(id)}`);
    Render.scan(box, data.scan, { showOpenLink: false });
  } catch (err) {
    box.textContent = err.message;
  }
})();
