/* =========================================================================
   graph.js - interactive relationship graph (Cytoscape.js).

   OSINTGraph.mount(container, graph) draws nodes/edges returned by the API
   (services/graph.py). Features: colour by entity type, red/orange ring for
   risky entities, click a node for details, click a legend chip to hide a
   type, fit / re-arrange / labels / export PNG.
   All labels are drawn on a canvas by Cytoscape, so third-party text can
   never be interpreted as HTML.
   ========================================================================= */
"use strict";

const OSINTGraph = (() => {
  const { el, cssVar } = OSINT;

  // entity type -> [legend label, light colour, dark colour, shape]
  const KINDS = {
    target:    ["Scan target", "#d1000b", "#ff3b45", "ellipse"],
    domain:    ["Domain", "#0f5e73", "#4fb6cc", "ellipse"],
    subdomain: ["Subdomain", "#3f8fa3", "#6fc3d6", "ellipse"],
    ip:        ["IP address", "#2459a6", "#7fb0f0", "round-rectangle"],
    host:      ["Server (NS / MX)", "#5a6f78", "#9ab0b8", "round-rectangle"],
    org:       ["Organisation", "#8a5a2b", "#d9a86c", "round-hexagon"],
    service:   ["Third-party service", "#1e8a57", "#5cc98e", "round-hexagon"],
    cert:      ["TLS certificate", "#0b6e77", "#5fc4cc", "round-tag"],
    account:   ["Platform account", "#2f6fb3", "#7fb0f0", "ellipse"],
    breach:    ["Breach", "#b03a5b", "#f08aa8", "round-triangle"],
    data:      ["Exposed data type", "#7d6a2d", "#d8c27a", "round-rectangle"],
    issue:     ["Risk issue", "#c2362b", "#f2887b", "round-diamond"],
    verdict:   ["Reputation verdict", "#a8640b", "#f0b356", "round-diamond"],
    tag:       ["Category", "#5a6f78", "#9ab0b8", "round-rectangle"],
  };
  const SEV_COLOR = { high: "--sev-high", medium: "--sev-medium", low: "--sev-low", info: "--rule-strong" };

  function isDark() { return OSINT.currentTheme() === "dark"; }
  function kindColor(kind) { const k = KINDS[kind] || KINDS.tag; return isDark() ? k[2] : k[1]; }

  function styles(caseMode = false) {
    const fs = caseMode ? 15 : 10;
    const ink = cssVar("--ink"), muted = cssVar("--muted"), rule = cssVar("--rule-strong"),
      surface = cssVar("--surface");
    return [
      { selector: "node", style: {
          "background-color": (n) => kindColor(n.data("kind")),
          "shape": (n) => (KINDS[n.data("kind")] || KINDS.tag)[3],
          "label": "data(short)", "color": ink, "font-family": "Public Sans, Segoe UI, sans-serif",
          "font-size": fs, "font-weight": 600, "text-valign": "bottom", "text-margin-y": 5,
          "min-zoomed-font-size": caseMode ? 9 : 6,
          "text-outline-color": surface, "text-outline-width": 2.5, "text-max-width": 110,
          "text-wrap": "ellipsis", "width": 22, "height": 22, "border-width": 0,
          "transition-property": "opacity", "transition-duration": 150 } },
      { selector: "node[severity = 'medium'], node[severity = 'high']", style: {
          "border-width": 4, "border-color": (n) => cssVar(SEV_COLOR[n.data("severity")]),
          "border-opacity": 0.9 } },
      { selector: "node[kind = 'issue'], node[kind = 'verdict'], node[kind = 'breach']", style: {
          "background-color": (n) => cssVar(SEV_COLOR[n.data("severity")] || "--sev-info"),
          "border-width": 0, "width": 20, "height": 20 } },
      { selector: "node[?root]", style: {
          "width": caseMode ? 60 : 46, "height": caseMode ? 60 : 46, "font-size": caseMode ? 26 : 13,
          "font-weight": 700, "label": "data(label)", "min-zoomed-font-size": 0,
          "text-max-width": 220, "border-width": 5, "border-color": cssVar("--target-wash"),
          "background-color": kindColor("target"), "shape": "ellipse" } },
      { selector: "node[shared > 1]", style: {
          "width": 40, "height": 40, "border-width": 6, "border-style": "double", "font-size": caseMode ? 20 : fs + 3,
          "min-zoomed-font-size": 0,
          "border-color": kindColor("target") } },
      { selector: "edge", style: {
          "width": 1.4, "line-color": rule, "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": rule, "arrow-scale": 0.7,
          "label": "data(label)", "font-size": 8.5, "color": muted, "text-rotation": "autorotate",
          "text-background-color": surface, "text-background-opacity": 1,
          "text-background-padding": 2, "text-opacity": 0 } },
      { selector: ".show-edge-labels edge", style: { "text-opacity": 1 } },
      { selector: "node:selected", style: { "overlay-color": cssVar("--accent"), "overlay-opacity": 0.18,
          "overlay-padding": 8 } },
      { selector: ".faded", style: { "opacity": 0.12 } },
      { selector: "edge.hl", style: { "line-color": cssVar("--accent"), "target-arrow-color": cssVar("--accent"),
          "width": 2.4, "text-opacity": 1 } },
    ];
  }

  function shortLabel(n) {
    const l = n.label || "";
    return l.length > 26 ? l.slice(0, 24) + "…" : l;
  }

  /* "Radar" layout for a single scan: the target sits in the centre, its
     direct entities form a ring grouped by type, and second-hop entities
     (e.g. the provider behind a mail server) sit outside their parent. */
  function radarPositions(cy) {
    const root = cy.nodes("[?root]").first();
    const pos = {};
    if (!root || root.empty()) return null;
    pos[root.id()] = { x: 0, y: 0 };
    const order = Object.keys(KINDS);
    const first = root.neighborhood("node").sort((a, b) =>
      (order.indexOf(a.data("kind")) - order.indexOf(b.data("kind"))) ||
      a.data("label").localeCompare(b.data("label")));
    // one empty slot between type groups makes the groups readable
    const slots = [];
    first.forEach((n, i) => {
      if (i && n.data("kind") !== first[i - 1].data("kind")) slots.push(null);
      slots.push(n);
    });
    // an ellipse (wider than tall) suits the wide graph panel and gives
    // horizontal labels room at the top and bottom of the ring
    const ry = Math.min(250, Math.max(140, slots.length * 7.5));
    const rx = ry * 2;
    const angle = {};
    slots.forEach((n, i) => {
      if (!n) return;
      const a = -Math.PI / 2 + (2 * Math.PI * i) / slots.length;
      angle[n.id()] = a;
      // near the top and bottom, neighbours sit side by side: stagger them
      // in and out so their labels do not collide
      const k = Math.abs(Math.sin(a)) > 0.75 && i % 2 ? 1.16 : 1;
      pos[n.id()] = { x: rx * k * Math.cos(a), y: ry * k * Math.sin(a) };
    });
    // second hop
    const r2x = rx + 170, r2y = ry + 95;
    const placed = new Set(Object.keys(pos));
    const outer = cy.nodes().filter((n) => !placed.has(n.id()));
    const byAngle = [];
    outer.forEach((n) => {
      const parents = n.neighborhood("node").filter((m) => angle[m.id()] !== undefined);
      let x = 0, y = 0;
      parents.forEach((m) => { x += Math.cos(angle[m.id()]); y += Math.sin(angle[m.id()]); });
      const a = parents.length ? Math.atan2(y, x) : Math.random() * 2 * Math.PI;
      byAngle.push([a, n]);
    });
    byAngle.sort((p, q) => p[0] - q[0]);
    const minGap = 0.16;      // keep outer labels apart
    let last = -Infinity;
    byAngle.forEach(([a, n]) => {
      const use = Math.max(a, last + minGap);
      last = use;
      pos[n.id()] = { x: r2x * Math.cos(use), y: r2y * Math.sin(use) };
    });
    return pos;
  }

  function layoutFor(cy, caseMode) {
    if (!caseMode) {
      const pos = radarPositions(cy);
      if (pos) return { name: "preset", positions: (n) => pos[n.id()], fit: true, padding: 40,
                        animate: true, animationDuration: 450 };
    }
    return { name: "cose", animate: true, animationDuration: 700, padding: 30, fit: true,
      nodeRepulsion: () => 20000, idealEdgeLength: () => 90, edgeElasticity: () => 60,
      gravity: 0.9, componentSpacing: 60, numIter: 2000, randomize: true, nodeDimensionsIncludeLabels: false };
  }

  function mount(container, graph, { caseMode = false, scanLinks = true } = {}) {
    container.replaceChildren();
    if (typeof cytoscape === "undefined") {
      container.append(el("p", { class: "graph-empty", text: "Graph library missing (static/js/vendor/cytoscape.min.js)." }));
      return null;
    }
    if (!graph || !graph.nodes || !graph.nodes.length) {
      container.append(el("div", { class: "graph-wrap" }, el("p", { class: "graph-empty",
        text: "No confirmed entities to map yet." })));
      return null;
    }

    const canvas = el("div", { class: "graph-canvas", role: "img",
      "aria-label": `Relationship graph with ${graph.nodes.length} entities and ${graph.edges.length} links` });
    const panel = el("div", { class: "node-panel", hidden: true });
    const btnLabels = el("button", { type: "button", class: "btn btn-small", "aria-pressed": "false", text: "Show link labels" });
    const toolbar = el("div", { class: "graph-toolbar" },
      el("button", { type: "button", class: "btn btn-small", text: "Fit to screen", onclick: () => cy.animate({ fit: { padding: 30 } }) }),
      el("button", { type: "button", class: "btn btn-small", text: "Re-arrange", onclick: () => relayout() }),
      btnLabels,
      el("button", { type: "button", class: "btn btn-small", text: "Export PNG", onclick: exportPng }),
      el("span", { class: "spacer" }),
      el("span", { class: "hint", text: caseMode
        ? "Double-ring nodes link different scans · zoom in to read every label"
        : "Click a node for details · scroll to zoom · drag to move" }));

    // legend with counts, doubling as a type filter
    const counts = {};
    graph.nodes.forEach((n) => { counts[n.kind] = (counts[n.kind] || 0) + 1; });
    const hidden = new Set();
    const legend = el("div", { class: "graph-legend", "aria-label": "Entity types (click to hide or show)" });
    Object.keys(KINDS).filter((k) => counts[k]).forEach((k) => {
      const dot = el("i");
      dot.style.background = ["issue", "verdict", "breach"].includes(k) ? cssVar("--sev-high") : kindColor(k);
      legend.append(el("button", { type: "button", class: "legend-item", "aria-pressed": "true",
        onclick: (e) => {
          const b = e.currentTarget;
          if (hidden.has(k)) hidden.delete(k); else hidden.add(k);
          b.setAttribute("aria-pressed", String(!hidden.has(k)));
          cy.nodes(`[kind = "${k}"]`).style("display", hidden.has(k) ? "none" : "element");
        } }, dot, KINDS[k][0], el("span", { class: "n", text: String(counts[k]) })));
    });

    const wrap = el("div", { class: "graph-wrap" }, toolbar, canvas, panel, legend);
    container.append(wrap);

    const elements = [
      ...graph.nodes.map((n) => ({ data: { ...n, short: shortLabel(n), shared: (n.targets || []).length } })),
      ...graph.edges.map((e) => ({ data: e })),
    ];
    const cy = cytoscape({ container: canvas, elements, style: styles(caseMode),
      minZoom: 0.2, maxZoom: 3, layout: { name: "preset" } });
    // Keep the key labels (scan targets, entities shared between scans) at a
    // readable on-screen size even when the whole graph is zoomed out.
    function keepKeyLabelsReadable() {
      const z = cy.zoom();
      cy.batch(() => {
        cy.nodes("[?root]").style({ "font-size": Math.max(13, 15 / z),
          "text-max-width": Math.max(220, 260 / z) });
        cy.nodes("[shared > 1][!root]").style({ "font-size": Math.max(10, 12 / z),
          "text-max-width": Math.max(160, 200 / z), "label": "data(label)" });
      });
    }
    function relayout() {
      // drop the enlarged labels first, or they would inflate the layout's bounds
      cy.off("zoom", keepKeyLabelsReadable);
      cy.nodes().removeStyle("font-size text-max-width label");
      const layout = cy.layout(layoutFor(cy, caseMode));
      layout.one("layoutstop", () => {
        cy.fit(undefined, 30);
        keepKeyLabelsReadable();
        cy.on("zoom", keepKeyLabelsReadable);
      });
      layout.run();
    }
    relayout();

    btnLabels.addEventListener("click", () => {
      const on = btnLabels.getAttribute("aria-pressed") !== "true";
      btnLabels.setAttribute("aria-pressed", String(on));
      btnLabels.textContent = on ? "Hide link labels" : "Show link labels";
      canvas.classList.toggle("show-edge-labels", on);
      cy.edges().style("text-opacity", on ? 1 : 0);
    });

    function showPanel(node) {
      const d = node.data();
      const links = node.connectedEdges().map((e) => {
        const other = e.source().id() === node.id() ? e.target() : e.source();
        const dir = e.source().id() === node.id() ? "→" : "←";
        return `${dir} ${e.data("label")}: ${other.data("label")}`;
      });
      panel.replaceChildren(
        el("button", { type: "button", class: "close", "aria-label": "Close details", text: "×",
          onclick: () => { panel.hidden = true; clearHighlight(); } }),
        el("div", { class: "kind", text: d.root ? "Scan target" : d.kind_label }),
        el("h3", { text: d.label }),
        d.severity !== "info" ? el("span", { class: "sev sev-badge-" + d.severity, text: d.severity + " risk" }) : null,
        d.detail ? el("p", { text: d.detail }) : null,
        links.length ? el("ul", {}, links.slice(0, 8).map((t) => el("li", { text: t }))) : null,
        links.length > 8 ? el("p", { class: "muted", text: `+ ${links.length - 8} more links` }) : null,
        scanLinks && d.scans && d.scans.length
          ? el("p", { class: "muted" }, "Found in scan ", ...d.scans.flatMap((id, i) =>
              [i ? ", " : "", el("a", { href: `/scan/${id}`, text: `#${id}` })])) : null);
      panel.hidden = false;
    }

    function clearHighlight() {
      cy.elements().removeClass("faded hl");
    }
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      clearHighlight();
      const hood = node.closedNeighborhood();
      cy.elements().not(hood).addClass("faded");
      hood.edges().addClass("hl");
      showPanel(node);
    });
    cy.on("tap", (evt) => { if (evt.target === cy) { clearHighlight(); panel.hidden = true; } });

    function exportPng() {
      const png = cy.png({ full: true, scale: 2, bg: cssVar("--surface") });
      const a = el("a", { href: "/", download: "reconlens-graph.png" });
      a.setAttribute("href", png);          // data: URL, generated locally
      document.body.append(a);
      a.click();
      a.remove();
    }

    document.addEventListener("themechange", () => cy.style(styles(caseMode)));
    return cy;
  }

  return { mount, KINDS };
})();
