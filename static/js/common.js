/* =========================================================================
   common.js - helpers shared by every page.

   Security rule for the whole frontend: data that came from an OSINT source
   (DNS records, breach descriptions, profile URLs...) is ALWAYS inserted with
   textContent via el(), never with innerHTML. Combined with the server's
   Content-Security-Policy this prevents cross-site scripting.
   ========================================================================= */
"use strict";

const OSINT = (() => {
  const STATUS_LABEL = {
    confirmed: "Confirmed", inconclusive: "Inconclusive",
    not_found: "Not found", error: "Error",
  };
  const TYPE_LABEL = {
    domain: "Domain intelligence", username: "Username footprint",
    email: "Email exposure", reputation: "IP & URL reputation",
  };

  /* Build a DOM element safely. attrs: {class, text, href, title, ...} */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key === "href") {
        // only allow web links and app-relative links (blocks javascript: URLs)
        if (/^(https?:\/\/|\/)/i.test(value)) node.setAttribute("href", value);
      } else if (key.startsWith("on") && typeof value === "function") {
        node.addEventListener(key.slice(2), value);
      } else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  /* fetch wrapper: JSON in, JSON out, readable errors */
  async function api(path, { method = "GET", body } = {}) {
    const opts = { method, headers: { Accept: "application/json" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let resp;
    try {
      resp = await fetch(path, opts);
    } catch (e) {
      throw Object.assign(new Error("Cannot reach the server. Is app.py still running?"), { data: {} });
    }
    let data = {};
    try { data = await resp.json(); } catch (e) { /* non-JSON body */ }
    if (!resp.ok || data.ok === false) {
      const message = (data.error && data.error.message) || `Request failed (HTTP ${resp.status})`;
      throw Object.assign(new Error(message), { status: resp.status, data: data.error || {} });
    }
    return data;
  }

  /* ---------------- demo / live mode (remembered per browser) ---------- */
  const liveAllowed = document.body.dataset.liveAllowed === "true";
  function storageGet(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function storageSet(key, v) { try { localStorage.setItem(key, v); } catch (e) { /* ignore */ } }

  let mode = storageGet("osint-mode") === "live" && liveAllowed ? "live" : "demo";

  function setMode(next) {
    mode = next === "live" && liveAllowed ? "live" : "demo";
    storageSet("osint-mode", mode);
    document.querySelectorAll(".mode-switch [data-mode]").forEach((b) =>
      b.setAttribute("aria-checked", String(b.dataset.mode === mode)));
    const banner = document.getElementById("mode-banner");
    const text = document.getElementById("mode-banner-text");
    if (banner && text) {
      banner.className = "mode-banner " + mode;
      text.textContent = mode === "demo"
        ? "Demo mode: every result is fictional and generated offline. Nothing real is queried."
        : "Live lookups: real public sources are queried. Only analyse assets you own or are authorised to assess.";
      // a dismissed notice stays hidden for this tab, but reappears when the mode changes
      banner.hidden = sessionGet("osint-banner-hidden") === mode;
    }
    document.dispatchEvent(new CustomEvent("modechange", { detail: mode }));
  }

  function sessionGet(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } }
  function sessionSet(key, v) { try { sessionStorage.setItem(key, v); } catch (e) { /* ignore */ } }

  /* Search: the quick-search strip under the navbar, or the big box on the overview. */
  function openSearch() {
    const quick = document.getElementById("quick-q");
    if (quick) {
      document.body.classList.add("search-open");
      quick.focus();
      return;
    }
    const hero = document.getElementById("hero-q");
    if (hero) { hero.scrollIntoView({ behavior: "smooth", block: "center" }); hero.focus(); }
  }

  function toast(message) {
    const t = document.getElementById("toast");
    if (!t) return;
    t.textContent = message;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
  }

  function fmtDate(iso) {
    if (!iso) return "–";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  /* ---------------- light / dark theme toggle (remembered per browser) */
  function currentTheme() {
    const set = document.documentElement.getAttribute("data-theme");
    if (set) return set;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function toggleTheme() {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    storageSet("osint-theme", next);
    document.dispatchEvent(new CustomEvent("themechange", { detail: next }));
  }

  /* ---------------- mobile navigation drawer */
  function setMenu(open) {
    const side = document.getElementById("sidebar");
    const scrim = document.getElementById("scrim");
    const btn = document.getElementById("menu-btn");
    if (!side) return;
    side.classList.toggle("open", open);
    document.body.classList.toggle("menu-open", open);
    if (scrim) scrim.hidden = !open;
    if (btn) btn.setAttribute("aria-expanded", String(open));
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".mode-switch [data-mode]").forEach((btn) =>
      btn.addEventListener("click", () => setMode(btn.dataset.mode)));
    setMode(mode);
    const themeBtn = document.getElementById("theme-btn");
    if (themeBtn) themeBtn.addEventListener("click", toggleTheme);
    const menuBtn = document.getElementById("menu-btn");
    if (menuBtn) menuBtn.addEventListener("click", () => setMenu(true));
    const menuClose = document.getElementById("menu-close");
    if (menuClose) menuClose.addEventListener("click", () => setMenu(false));
    const scrim = document.getElementById("scrim");
    if (scrim) scrim.addEventListener("click", () => setMenu(false));
    const bannerClose = document.getElementById("banner-close");
    if (bannerClose) bannerClose.addEventListener("click", () => {
      document.getElementById("mode-banner").hidden = true;
      sessionSet("osint-banner-hidden", mode);
    });
    const searchBtn = document.getElementById("search-btn");
    if (searchBtn) searchBtn.addEventListener("click", () => {
      if (document.body.classList.contains("search-open")) document.body.classList.remove("search-open");
      else openSearch();
    });
    // dropdown menus: open on click too (touch screens and keyboard users)
    document.querySelectorAll(".nav-drop-btn").forEach((btn) => btn.addEventListener("click", () => {
      const drop = btn.parentElement;
      const open = !drop.classList.contains("open");
      document.querySelectorAll(".nav-drop.open").forEach((d) => d.classList.remove("open"));
      drop.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
    }));
    document.addEventListener("click", (e) => {
      if (!e.target.closest(".nav-drop")) {
        document.querySelectorAll(".nav-drop.open").forEach((d) => d.classList.remove("open"));
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      setMenu(false);
      document.body.classList.remove("search-open");
      document.querySelectorAll(".nav-drop.open").forEach((d) => d.classList.remove("open"));
    });
  });

  return {
    el, api, toast, fmtDate, cssVar, STATUS_LABEL, TYPE_LABEL,
    getMode: () => mode, setMode, currentTheme, openSearch,
  };
})();
