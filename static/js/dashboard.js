/* =========================================================================
   dashboard.js - overview page: sample investigations, KPIs, the figure
   carousel (four charts) and recent scans.
   ========================================================================= */
"use strict";

(async () => {
  const { api, el, STATUS_LABEL, TYPE_LABEL, getMode, setMode } = OSINT;
  const TYPE_SHORT = { domain: "Domain", username: "Username", email: "Email", reputation: "IP / URL" };
  const LEVELS = ["Low", "Moderate", "High", "Critical"];
  const charts = [];

  // sample cards: one click runs a fictional demo investigation
  try {
    const { demo_targets: demo } = await api("/api/demo-targets");
    const box = document.getElementById("samples");
    for (const type of ["domain", "email", "reputation", "username"]) {
      for (const t of demo[type] || []) {
        box.append(el("button", { type: "button", class: "sample", onclick: () => {
            if (getMode() !== "demo") setMode("demo");
            SmartSearch.go(type, t.target);
          } },
          el("span", { class: "sample-type", text: TYPE_SHORT[type] }),
          el("b", { text: t.target }),
          el("small", { text: t.label })));
      }
    }
  } catch (e) { /* samples are optional */ }

  /* ------------------------------------------------------------ carousel */
  function carousel() {
    const root = document.getElementById("fig-carousel");
    const track = document.getElementById("fig-track");
    const dotsBox = document.getElementById("fig-dots");
    if (!root || !track) return;
    const slides = [...track.children];
    const dots = slides.map((s, i) => el("button", { type: "button", role: "tab",
      "aria-label": `Figure ${i + 1}`, onclick: () => show(i) }));
    dotsBox.append(...dots);
    let index = 0;
    function show(i) {
      index = (i + slides.length) % slides.length;
      track.style.setProperty("--i", String(index));
      slides.forEach((s, j) => {
        s.classList.toggle("is-active", j === index);
        s.setAttribute("aria-hidden", String(j !== index));
        s.querySelectorAll("a").forEach((a) => { a.tabIndex = j === index ? 0 : -1; });
      });
      dots.forEach((d, j) => d.setAttribute("aria-selected", String(j === index)));
    }
    // clicking a dimmed neighbour brings it to the centre
    slides.forEach((s, j) => s.addEventListener("click", (e) => {
      if (j !== index) { e.preventDefault(); show(j); }
    }));
    root.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight") show(index + 1);
      if (e.key === "ArrowLeft") show(index - 1);
    });
    let startX = null;
    track.addEventListener("pointerdown", (e) => { startX = e.clientX; });
    track.addEventListener("pointerup", (e) => {
      if (startX !== null && Math.abs(e.clientX - startX) > 50) show(index + (e.clientX < startX ? 1 : -1));
      startX = null;
    });
    show(0);
  }
  carousel();

  /* -------------------------------------------------------------- charts */
  // The charts sit on a white "figure" card, so colours are read from that
  // card (it defines its own light palette) instead of the page theme.
  function drawCharts(s, recent) {
    charts.splice(0).forEach((c) => c.destroy());
    if (typeof Chart === "undefined") return;
    const fig = document.querySelector(".figure");
    const v = (name) => getComputedStyle(fig).getPropertyValue(name).trim();
    const ink = v("--fig-ink"), tick = v("--fig-muted"), grid = v("--fig-rule");
    const lvColor = (lv) => v("--lv-" + lv.toLowerCase());
    const font = { family: "Public Sans, Segoe UI, sans-serif" };
    Chart.defaults.font.family = font.family;
    const axes = (max) => ({
      x: { ticks: { color: ink, font: { size: 11 } }, grid: { display: false }, border: { color: grid } },
      y: { min: 0, max, ticks: { color: tick, precision: 0 }, grid: { color: grid }, border: { display: false } },
    });

    const last = recent.slice(0, 10).reverse();
    charts.push(new Chart(document.getElementById("chart-scores"), {
      type: "bar",
      data: { labels: last.map((x) => x.target.length > 18 ? x.target.slice(0, 17) + "…" : x.target),
              datasets: [{ data: last.map((x) => x.exposure_score),
                           backgroundColor: last.map((x) => lvColor(x.exposure_level)),
                           borderRadius: 3, maxBarThickness: 34, minBarLength: 3 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false },
                   tooltip: { callbacks: { label: (c) => ` ${c.raw}/100 · ${last[c.dataIndex].exposure_level}` } } },
                 scales: axes(100) },
    }));

    const statuses = ["confirmed", "inconclusive", "not_found", "error"];
    charts.push(new Chart(document.getElementById("chart-status"), {
      type: "doughnut",
      data: { labels: statuses.map((k) => STATUS_LABEL[k]),
              datasets: [{ data: statuses.map((k) => s.findings_by_status[k] || 0),
                           backgroundColor: statuses.map((k) => v("--st-" + k)), borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "64%",
                 plugins: { legend: { position: "right", labels: { color: ink, boxWidth: 12, boxHeight: 12 } } } },
    }));

    charts.push(new Chart(document.getElementById("chart-levels"), {
      type: "bar",
      data: { labels: LEVELS,
              datasets: [{ data: LEVELS.map((l) => s.scans_by_level[l] || 0),
                           backgroundColor: LEVELS.map(lvColor), borderRadius: 3, maxBarThickness: 60 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } },
                 scales: axes(undefined) },
    }));

    const types = Object.keys(TYPE_LABEL);
    charts.push(new Chart(document.getElementById("chart-types"), {
      type: "doughnut",
      data: { labels: types.map((t) => TYPE_LABEL[t]),
              datasets: [{ data: types.map((t) => s.scans_by_type[t] || 0),
                           backgroundColor: [v("--fig-c1"), v("--fig-c2"), v("--fig-c3"), v("--fig-c4")],
                           borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "64%",
                 plugins: { legend: { position: "right", labels: { color: ink, boxWidth: 12, boxHeight: 12 } } } },
    }));
  }

  try {
    const [statsRes, recent, graph] = await Promise.all([
      api("/api/stats"), api("/api/scans?limit=10"), api("/api/graph?limit=20")]);
    const s = statsRes.stats;
    document.getElementById("kpi-total").textContent = String(s.total_scans);
    document.getElementById("kpi-avg").textContent = s.average_score === null ? "–" : `${Math.round(s.average_score)}/100`;
    document.getElementById("kpi-nodes").textContent = String(graph.graph.stats.nodes || 0);
    document.getElementById("kpi-shared").textContent = String(graph.graph.stats.shared_nodes || 0);
    drawCharts(s, recent.scans);
    document.addEventListener("themechange", () => drawCharts(s, recent.scans));
    Render.scanTable(document.getElementById("recent"), recent.scans);
  } catch (err) {
    document.getElementById("recent").textContent = err.message;
  }
})();
