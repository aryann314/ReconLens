/* =========================================================================
   history.js - list, filter and delete stored scans.
   ========================================================================= */
"use strict";

(() => {
  const { api, toast } = OSINT;
  const box = document.getElementById("history-table");
  const seg = document.getElementById("filter-type");
  const text = document.getElementById("filter-text");
  let type = "";
  let all = [];

  function paint() {
    const q = text.value.trim().toLowerCase();
    Render.scanTable(box, q ? all.filter((s) => s.target.toLowerCase().includes(q)) : all,
      { onDelete: remove });
  }

  async function load() {
    try {
      const data = await api("/api/scans?limit=200" + (type ? `&type=${encodeURIComponent(type)}` : ""));
      all = data.scans;
      paint();
    } catch (err) {
      box.textContent = err.message;
    }
  }

  async function remove(scan) {
    if (!window.confirm(`Delete scan #${scan.id} (${scan.target})? This cannot be undone.`)) return;
    try {
      await api(`/api/scans/${scan.id}`, { method: "DELETE" });
      toast(`Scan #${scan.id} deleted.`);
      load();
    } catch (err) {
      toast(err.message);
    }
  }

  seg.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    type = b.dataset.type;
    seg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-checked", String(x === b)));
    load();
  }));
  text.addEventListener("input", paint);
  load();
})();
