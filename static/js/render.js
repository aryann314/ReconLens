/* =========================================================================
   render.js - draws a scan result (used by the four analysis pages and the
   scan detail page) and the scan list table (overview and history pages).
   ========================================================================= */
"use strict";

const Render = (() => {
  const { el, fmtDate, STATUS_LABEL, TYPE_LABEL, cssVar } = OSINT;
  const STATUS_ORDER = { confirmed: 0, inconclusive: 1, error: 2, not_found: 3 };
  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  const MONO_MODULES = new Set(["dns", "crtsh", "rdap", "tls"]);
  const MODULE_TITLE = {
    rdap: "Registration data (RDAP / WHOIS)", dns: "DNS records and email security",
    crtsh: "Certificate transparency", tls: "TLS certificate", username: "Platform profiles",
    hibp: "Breach exposure", virustotal: "Vendor reputation",
  };

  /* ---------------------------------------------------- exposure gauge */
  function gauge(score, level) {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 200 112");
    svg.setAttribute("aria-hidden", "true");
    const d = "M 20 100 A 80 80 0 0 1 180 100";
    const len = Math.PI * 80;
    const track = document.createElementNS(NS, "path");
    track.setAttribute("d", d);
    track.setAttribute("class", "track");
    const fill = document.createElementNS(NS, "path");
    fill.setAttribute("d", d);
    fill.setAttribute("class", "fill lv-" + level);
    fill.style.strokeDasharray = String(len);
    fill.style.strokeDashoffset = String(len);
    svg.append(track, fill);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      fill.style.strokeDashoffset = String(len * (1 - Math.min(score, 100) / 100));
    }));
    return el("div", { class: "gauge", role: "img",
                       "aria-label": `Exposure score ${score} of 100, ${level}` },
      svg,
      el("div", { class: "gauge-score" }, String(score), el("small", { text: " / 100" })),
      el("div", { class: "gauge-level lv-" + level, text: level + " exposure" }));
  }

  /* ----------------------------------------- certainty bar (signature) */
  function certainty(counts) {
    const order = ["confirmed", "inconclusive", "not_found", "error"];
    const total = order.reduce((s, k) => s + (counts[k] || 0), 0) || 1;
    const bar = el("div", { class: "certainty-bar", role: "img",
      "aria-label": order.map((k) => `${STATUS_LABEL[k]} ${counts[k] || 0}`).join(", ") });
    const legend = el("div", { class: "certainty-legend" });
    for (const k of order) {
      const n = counts[k] || 0;
      if (n) {
        const seg = el("span", { class: "seg-" + k, title: `${STATUS_LABEL[k]}: ${n}` });
        seg.style.flexGrow = String(n);
        seg.style.flexBasis = "0";
        bar.append(seg);
      }
      legend.append(el("span", {}, el("i", { class: "seg-" + k }),
        `${STATUS_LABEL[k]} `, el("strong", { text: String(n) })));
    }
    return el("div", {}, el("div", { class: "certainty-title",
      text: "How certain are these results?" }), bar, legend);
  }

  /* ------------------------------------------------------------- tables */
  function dataTable(table, mono) {
    const thead = el("thead", {}, el("tr", {}, table.columns.map((c) => el("th", { text: c }))));
    const tbody = el("tbody", {}, table.rows.map((row) =>
      el("tr", {}, row.map((cell) => el("td", { class: mono ? "mono" : null,
                                                text: cell === null ? "" : String(cell) })))));
    return el("div", { class: "table-wrap" }, el("table", { class: "data" }, thead, tbody));
  }

  function detailsBlock(f) {
    const d = f.details || {};
    const parts = [];
    if (d.table && d.table.rows && d.table.rows.length) {
      parts.push(dataTable(d.table, MONO_MODULES.has(f.module)));
      if (d.truncated) parts.push(el("p", { class: "muted", text: "Showing the first rows only - export CSV for all." }));
    }
    const skip = new Set(["table", "chart", "note", "truncated"]);
    const kv = Object.entries(d).filter(([k, v]) => !skip.has(k) && v !== null && v !== "" &&
      !(Array.isArray(v) && !v.length));
    if (kv.length && !(d.table && d.table.rows && d.table.rows.length)) {
      parts.push(el("dl", { class: "kv" }, kv.map(([k, v]) => [
        el("dt", { text: k.replace(/_/g, " ") }),
        el("dd", { text: Array.isArray(v) ? v.join(", ") : String(v) })])));
    }
    if (d.note) parts.push(el("p", { class: "muted", text: d.note }));
    if (!parts.length) return null;
    const label = d.table && d.table.rows && d.table.rows.length
      ? `Show ${d.table.rows.length} rows` : "Details";
    return el("details", {}, el("summary", { text: label }), ...parts);
  }

  function findingRow(f) {
    const tags = el("div", { class: "finding-tags" });
    if (f.status === "confirmed" && f.severity !== "info") {
      tags.append(el("span", { class: "sev sev-badge-" + f.severity, text: f.severity }));
    }
    tags.append(el("span", { class: "pill st-" + f.status, text: STATUS_LABEL[f.status] }));
    const meta = el("div", { class: "finding-meta" }, `${f.source} · collected ${fmtDate(f.collected_at)}`);
    if (f.source_url) {
      meta.append(" · ", el("a", { href: f.source_url, target: "_blank",
        rel: "noopener noreferrer", text: "view source" }));
    }
    return el("li", { class: "finding sev-" + (f.status === "confirmed" ? f.severity : "info") },
      el("div", {}, el("div", { class: "finding-title", text: f.title }),
        f.value ? el("div", { class: "finding-value", text: f.value }) : null),
      tags, meta, detailsBlock(f));
  }

  function sortFindings(list) {
    return [...list].sort((a, b) => (STATUS_ORDER[a.status] - STATUS_ORDER[b.status]) ||
      (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]));
  }

  /* --------------------------------------------- username: 3-way split */
  function usernameBody(findings) {
    const frag = document.createDocumentFragment();
    const reuse = findings.find((f) => f.code === "USERNAME_REUSE");
    if (reuse) {
      frag.append(el("p", { class: "callout" }, el("strong", { text: reuse.title + ". " }), reuse.value));
    }
    const groups = [
      ["confirmed", "Profile found"], ["inconclusive", "Inconclusive"], ["not_found", "Not found"],
    ];
    const cols = el("div", { class: "columns-3" });
    for (const [status, title] of groups) {
      const items = findings.filter((f) => f.status === status && f.code !== "USERNAME_REUSE");
      const list = el("ul", { class: "platforms" });
      if (!items.length) list.append(el("li", { class: "muted", text: "None" }));
      for (const f of items) {
        const reason = (f.details && f.details.reason) || "";
        list.append(el("li", {},
          status === "confirmed"
            ? el("a", { href: f.source_url, target: "_blank", rel: "noopener noreferrer", text: f.title })
            : el("span", { text: f.title }),
          el("small", { text: [f.details && f.details.category, reason].filter(Boolean).join(" - ") })));
      }
      cols.append(el("div", {}, el("div", { class: "col-title" },
        el("span", { class: "st-" + status, text: title }),
        el("span", { class: "count", text: String(items.length) })), list));
    }
    frag.append(cols);
    const errors = findings.filter((f) => f.status === "error");
    if (errors.length) frag.append(el("ul", { class: "findings" }, errors.map(findingRow)));
    return frag;
  }

  /* ------------------------------------------- vendor-verdict chart */
  function verdictChart(findings) {
    const stats = findings.find((f) => f.code === "VT_STATS" && f.details && f.details.chart);
    if (!stats || typeof Chart === "undefined") return null;
    const entries = Object.entries(stats.details.chart).filter(([, v]) => v > 0);
    const colorFor = { malicious: "--sev-high", suspicious: "--sev-medium",
      harmless: "--lv-low", undetected: "--st-not_found", timeout: "--rule-strong" };
    const canvas = el("canvas", { role: "img", "aria-label": stats.value });
    const box = el("div", { class: "chart-inline" }, canvas);
    requestAnimationFrame(() => new Chart(canvas, {
      type: "doughnut",
      data: { labels: entries.map(([k]) => k),
              datasets: [{ data: entries.map(([, v]) => v),
                           backgroundColor: entries.map(([k]) => cssVar(colorFor[k] || "--muted")),
                           borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "62%",
                 plugins: { legend: { position: "right", labels: { color: cssVar("--ink") } } } },
    }));
    return box;
  }

  /* ---------------------------------------------------- tabs helper */
  function tabs(container, defs, initial = 0) {
    const bar = el("div", { class: "tabs", role: "tablist" });
    const panels = [];
    const built = new Set();
    defs.forEach((d, i) => {
      const id = `tab-${d.key}`;
      const btn = el("button", { type: "button", role: "tab", id, "aria-selected": "false",
        "aria-controls": id + "-panel", onclick: () => select(i) },
        d.label, d.count !== undefined ? el("span", { class: "count", text: String(d.count) }) : null);
      bar.append(btn);
      panels.push(el("div", { class: "tabpanel", role: "tabpanel", id: id + "-panel",
        "aria-labelledby": id, hidden: true }));
    });
    function select(i) {
      [...bar.children].forEach((b, j) => b.setAttribute("aria-selected", String(i === j)));
      panels.forEach((p, j) => { p.hidden = i !== j; });
      if (!built.has(i)) { built.add(i); defs[i].build(panels[i]); }   // lazy: graph needs a visible box
    }
    bar.addEventListener("keydown", (e) => {
      const cur = [...bar.children].findIndex((b) => b.getAttribute("aria-selected") === "true");
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        const next = (cur + (e.key === "ArrowRight" ? 1 : -1) + defs.length) % defs.length;
        select(next); bar.children[next].focus();
      }
    });
    container.append(bar, ...panels);
    select(initial);
    return { select };
  }

  /* --------------------------------------------------------- full scan */
  function scan(container, s, { showOpenLink = true } = {}) {
    container.replaceChildren();
    const counts = (s.scoring && s.scoring.status_counts) || {};
    const findings = s.findings || [];
    const graph = s.graph || { nodes: [], edges: [], stats: {} };

    const actions = el("div", { class: "actions" },
      el("a", { class: "btn btn-small btn-primary", href: `/api/scans/${s.id}/report.pdf`, text: "Download PDF report" }),
      el("a", { class: "btn btn-small", href: `/api/scans/${s.id}/report.csv`, text: "Download CSV" }),
      el("a", { class: "btn btn-small", href: `/graph?add=${s.id}`, text: "Add to investigation graph" }),
      showOpenLink ? el("a", { class: "btn btn-small", href: `/scan/${s.id}`, text: "Open as page" }) : null);

    container.append(el("section", { class: "summary" },
      gauge(s.exposure_score, s.exposure_level),
      el("div", { class: "summary-body" },
        el("div", {},
          el("div", { class: "summary-target", text: s.target }),
          el("div", { class: "meta-row" },
            el("span", { class: "tag tag-" + s.mode, text: s.mode === "demo" ? "Demo data" : "Live lookup" }),
            el("span", {}, TYPE_LABEL[s.scan_type]),
            el("span", {}, "Scan ", el("strong", { text: "#" + s.id })),
            el("span", {}, "Status ", el("strong", { text: s.status })),
            el("span", {}, fmtDate(s.started_at)),
            el("span", {}, (s.duration_ms || 0) < 1 ? "under 1 ms" : (s.duration_ms || 0) < 1000 ? `${s.duration_ms} ms`
              : `${(s.duration_ms / 1000).toFixed(1)} s`))),
        certainty(counts),
        actions)));

    const recs = s.recommendations || [];
    tabs(container, [
      { key: "overview", label: "Overview", build: (p) => overviewTab(p, s, graph) },
      { key: "graph", label: "Relationship graph", count: (graph.nodes || []).length,
        build: (p) => OSINTGraph.mount(p, graph) },
      { key: "findings", label: "Findings", count: findings.length, build: (p) => findingsTab(p, s) },
      { key: "actions", label: "What to do next", count: recs.length, build: (p) => actionsTab(p, recs) },
      { key: "limits", label: "Limitations", build: (p) => p.append(el("section", { class: "result-section" },
          el("ul", { class: "limits" }, (s.limitations || []).map((l) => el("li", { text: l }))))) },
    ]);
  }

  function overviewTab(p, s, graph) {
    const risky = sortFindings((s.findings || []).filter((f) => f.status === "confirmed" &&
      f.severity !== "info" && f.code !== "USERNAME_FOUND"));
    const riskList = risky.length
      ? el("ul", { class: "risk-list" }, risky.slice(0, 6).map((f) => el("li", {},
          el("span", { class: "sev sev-badge-" + f.severity, text: f.severity }),
          el("div", {}, el("div", { class: "risk-title", text: f.title }),
            f.value ? el("div", { class: "risk-value", text: f.value }) : null))))
      : el("p", { class: "muted", text: "No confirmed risk indicators. Nice." });
    const st = graph.stats || {};
    const bd = (s.scoring && s.scoring.breakdown) || [];
    p.append(el("div", { class: "two-col" },
      el("section", { class: "result-section" },
        el("div", { class: "section-head" }, el("h2", { text: "Top risk indicators" }),
          el("span", { class: "section-meta", text: `${risky.length} confirmed` })),
        riskList),
      el("div", { class: "tabpanel" },
        el("section", { class: "result-section" },
          el("div", { class: "section-head" }, el("h2", { text: "Intelligence map" })),
          el("div", { class: "graph-stats" },
            el("span", {}, el("b", { text: String(st.nodes || 0) }), "entities"),
            el("span", {}, el("b", { text: String(st.edges || 0) }), "relationships"),
            el("span", {}, el("b", { text: String(st.risky_nodes || 0) }), "flagged"))),
        el("section", { class: "result-section" },
          el("div", { class: "section-head" }, el("h2", { text: "Sources queried" })),
          el("ul", { class: "source-status" }, (s.modules || []).map((m) => el("li", {},
            el("span", { text: MODULE_TITLE[m.module] || m.source }),
            el("span", {}, el("span", { class: "module-state " + m.status, text: m.status }),
              el("span", { class: "muted", text: ` · ${m.duration_ms} ms` })))))))));
    p.append(el("section", { class: "result-section" },
      el("div", { class: "section-head" }, el("h2", { text: `How the score of ${s.exposure_score} was calculated` })),
      el("p", { class: "method", text: s.scoring ? s.scoring.method : "" }),
      bd.length ? dataTable({ columns: ["Confirmed finding", "Severity", "Points"],
                              rows: bd.map((b) => [b.title, b.severity, `+${b.points}`]) }, false)
                : el("p", { class: "muted", text: "No confirmed finding added points." })));
  }

  function findingsTab(p, s) {
    for (const m of s.modules || []) {
      const items = sortFindings((s.findings || []).filter((f) => f.module === m.module));
      const section = el("section", { class: "result-section" },
        el("div", { class: "section-head" },
          el("h2", { text: MODULE_TITLE[m.module] || m.source }),
          el("span", { class: "section-meta" }, m.source, " · ",
            el("span", { class: "module-state " + m.status, text: m.status }),
            ` · ${m.duration_ms} ms`)));
      if (m.error && m.status !== "ok") section.append(el("p", { class: "section-note", text: m.error }));
      if (m.module === "username") section.append(usernameBody(items));
      else {
        const chart = m.module === "virustotal" ? verdictChart(items) : null;
        if (chart) section.append(chart);
        const visible = m.error ? items.filter((f) => f.status !== "error") : items;
        if (visible.length) section.append(el("ul", { class: "findings" }, visible.map(findingRow)));
      }
      p.append(section);
    }
  }

  function actionsTab(p, recs) {
    if (!recs.length) { p.append(el("p", { class: "muted", text: "No recommendations." })); return; }
    p.append(el("section", { class: "result-section" },
      el("div", { class: "section-head" }, el("h2", { text: "Recommended actions" }),
        el("span", { class: "section-meta", text: "Ordered by priority" })),
      el("ul", { class: "recs" }, recs.map((r) => el("li", {},
        el("span", { class: "prio prio-" + r.priority, text: r.priority }),
        el("div", {},
          el("div", { class: "rec-title", text: r.title }),
          el("p", { class: "rec-action", text: r.action }),
          r.triggered_by && r.triggered_by.length
            ? el("div", { class: "rec-trigger", text: "Because: " + r.triggered_by.join("; ") }) : null))))));
  }

  /* ---------------------------------------------------- scan list table */
  function scanTable(container, scans, { onDelete } = {}) {
    container.replaceChildren();
    if (!scans.length) {
      container.append(el("div", { class: "empty-state" },
        el("p", { text: "No scans yet. Run a demo scan from one of the analysis pages to get started." }),
        el("a", { class: "btn btn-primary", href: "/domain", text: "Analyse a domain" })));
      return;
    }
    const head = ["#", "Module", "Target", "Mode", "Exposure", "Findings", "When", ""];
    const rows = scans.map((s) => el("tr", {},
      el("td", { text: String(s.id) }),
      el("td", { text: TYPE_LABEL[s.scan_type] }),
      el("td", { class: "mono" }, el("a", { href: `/scan/${s.id}`, text: s.target })),
      el("td", {}, el("span", { class: "tag tag-" + s.mode, text: s.mode })),
      el("td", {}, el("span", { class: "score-chip lv-" + s.exposure_level },
        el("span", { text: String(s.exposure_score) }), el("small", { text: s.exposure_level }))),
      el("td", { text: String(s.finding_count ?? "") }),
      el("td", { text: fmtDate(s.started_at) }),
      el("td", {}, onDelete ? el("button", { class: "btn btn-small btn-danger", type: "button",
        text: "Delete", "aria-label": `Delete scan ${s.id}`, onclick: () => onDelete(s) }) : null)));
    container.append(el("div", { class: "table-wrap" }, el("table", { class: "data" },
      el("thead", {}, el("tr", {}, head.map((h) => el("th", { text: h })))),
      el("tbody", {}, rows))));
  }

  return { scan, scanTable };
})();
