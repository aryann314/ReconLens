/* =========================================================================
   case_graph.js - Investigation graph page: merge several stored scans into
   one correlated graph. Entities discovered by more than one scan (drawn
   with a double ring) are the links between separate investigations.
   ========================================================================= */
"use strict";

(async () => {
  const { api, el, TYPE_LABEL, toast } = OSINT;
  const list = document.getElementById("case-list");
  const stats = document.getElementById("case-stats");
  const graphBox = document.getElementById("case-graph");
  const selected = new Set();
  let timer = null;

  async function draw() {
    if (!selected.size) {
      stats.replaceChildren();
      graphBox.replaceChildren(el("div", { class: "graph-wrap" }, el("p", { class: "graph-empty",
        text: "Select at least one scan to build the investigation graph." })));
      return;
    }
    try {
      const { graph } = await api(`/api/graph?ids=${[...selected].join(",")}`);
      const st = graph.stats;
      stats.replaceChildren(el("div", { class: "panel graph-stats" },
        el("span", {}, el("b", { text: String(st.scans) }), "scans merged"),
        el("span", {}, el("b", { text: String(st.nodes) }), "entities"),
        el("span", {}, el("b", { text: String(st.edges) }), "relationships"),
        el("span", {}, el("b", { text: String(st.shared_nodes) }), "shared entities (links between scans)"),
        el("span", {}, el("b", { text: String(st.risky_nodes) }), "flagged as risky")));
      OSINTGraph.mount(graphBox, graph, { caseMode: true });
    } catch (err) {
      toast(err.message);
    }
  }
  const redraw = () => { clearTimeout(timer); timer = setTimeout(draw, 200); };

  try {
    const { scans } = await api("/api/scans?limit=50");
    list.replaceChildren();
    if (!scans.length) {
      list.append(el("li", { class: "muted" }, "No scans yet. ",
        el("a", { href: "/", text: "Run a sample investigation" }), " first."));
    }
    const want = new URLSearchParams(window.location.search).get("add");
    scans.forEach((s, i) => {
      const on = want ? String(s.id) === want || i < 8 : i < 8;
      if (on) selected.add(s.id);
      const box = el("input", { type: "checkbox", value: String(s.id) });
      box.checked = on;
      box.addEventListener("change", () => {
        if (box.checked) selected.add(s.id); else selected.delete(s.id);
        redraw();
      });
      list.append(el("li", {}, el("label", {}, box,
        el("span", { class: "t" }, s.target, el("small", { text: `#${s.id} · ${TYPE_LABEL[s.scan_type]}` })),
        el("span", { class: "score-chip lv-" + s.exposure_level, text: String(s.exposure_score) }))));
    });
    document.getElementById("case-all").addEventListener("click", () => {
      list.querySelectorAll("input").forEach((b) => { b.checked = true; selected.add(Number(b.value)); });
      redraw();
    });
    document.getElementById("case-none").addEventListener("click", () => {
      list.querySelectorAll("input").forEach((b) => { b.checked = false; });
      selected.clear();
      redraw();
    });
    draw();
  } catch (err) {
    list.replaceChildren(el("li", { text: err.message }));
  }
})();
