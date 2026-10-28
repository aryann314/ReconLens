/* =========================================================================
   scan_form.js - the analysis pages (domain, username, email, reputation).
   Loads demo targets, enforces the authorisation checkbox in live mode,
   submits the scan and renders the result.
   ========================================================================= */
"use strict";

(() => {
  const { el, api, getMode, toast } = OSINT;
  const form = document.getElementById("scan-form");
  const scanType = form.dataset.scanType;
  const input = document.getElementById("target");
  const errorBox = document.getElementById("target-error");
  const runBtn = document.getElementById("run-btn");
  const authBox = document.getElementById("auth-notice");
  const authCheck = document.getElementById("authorized");
  const demoBox = document.getElementById("demo-targets");
  const chips = document.getElementById("demo-chips");
  const results = document.getElementById("results");

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = !message;
    input.setAttribute("aria-invalid", message ? "true" : "false");
  }

  function applyMode(mode) {
    const live = mode === "live";
    authBox.hidden = !live;
    demoBox.hidden = live;
    authCheck.checked = false;
    showError("");
  }

  async function loadDemoTargets() {
    try {
      const data = await api("/api/demo-targets");
      for (const t of data.demo_targets[scanType] || []) {
        chips.append(el("button", { type: "button", class: "chip",
          onclick: () => { input.value = t.target; showError(""); input.focus(); } },
          el("b", { text: t.target }), el("span", { text: " - " + t.label })));
      }
    } catch (e) { /* chips are a convenience only */ }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = input.value.trim();
    const mode = getMode();
    if (!target) return showError("Enter a value to analyse.");
    if (mode === "live" && !authCheck.checked) {
      authCheck.focus();
      return showError("Tick the authorisation statement before running a live lookup.");
    }
    showError("");
    runBtn.disabled = true;
    runBtn.textContent = "Analysing…";
    const steps = ["Validating input", "Collecting public intelligence", "Correlating entities",
      "Scoring exposure"].map((t) => el("span", { text: t }));
    results.replaceChildren(el("div", { class: "progress" }, el("div", { class: "spinner" }),
      el("div", { class: "progress-steps" }, ...steps,
        el("small", { class: "muted", text: mode === "live"
          ? "Querying public sources. Certificate logs can take up to 30 seconds."
          : "Generating the fictional demo result…" }))));
    let step = 0;
    steps[0].classList.add("on");
    const ticker = setInterval(() => {
      if (step < steps.length - 1) { steps[step].classList.remove("on"); steps[++step].classList.add("on"); }
    }, mode === "live" ? 2500 : 250);

    try {
      const data = await api(`/api/scan/${scanType}`, {
        method: "POST", body: { target, mode, authorized: mode === "live" && authCheck.checked } });
      Render.scan(results, data.scan);
      results.scrollIntoView({ behavior: "smooth", block: "start" });
      toast(`Scan #${data.scan.id} saved - exposure score ${data.scan.exposure_score}.`);
    } catch (err) {
      results.replaceChildren();
      let msg = err.message;
      if (err.data && err.data.code === "not_a_demo_target") {
        msg += " Pick one of the demo targets below, or switch to Live lookups.";
      }
      showError(msg);
    } finally {
      clearInterval(ticker);
      runBtn.disabled = false;
      runBtn.textContent = "Run analysis";
    }
  });

  document.addEventListener("modechange", (e) => applyMode(e.detail));
  applyMode(getMode());
  loadDemoTargets();

  // Arrived from the smart search (?target=...&run=1): fill in and run.
  const params = new URLSearchParams(window.location.search);
  const preset = params.get("target");
  if (preset) {
    input.value = preset.slice(0, 2048);
    history.replaceState(null, "", window.location.pathname);
    if (params.get("run") === "1") {
      if (getMode() === "live") {
        authCheck.focus();
        showError("Confirm the authorisation statement, then press Run analysis.");
      } else {
        form.requestSubmit();
      }
    }
  }
})();
