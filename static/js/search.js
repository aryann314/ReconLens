/* =========================================================================
   search.js - "type anything" smart search.

   The user types one value; we detect what kind of target it is and send
   them to the matching module, which runs the scan automatically:
       contains @                 -> email exposure
       http(s)://...  or an IP    -> IP & URL reputation
       name.with.dots             -> domain intelligence
       anything else              -> username footprint
   The detection can always be overridden with the type pills.
   ========================================================================= */
"use strict";

const SmartSearch = (() => {
  const { el } = OSINT;
  const TYPES = [
    ["domain", "Domain"], ["email", "Email"], ["reputation", "IP / URL"], ["username", "Username"],
  ];
  const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

  function detect(raw) {
    const q = (raw || "").trim();
    if (!q) return null;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) return "email";
    if (/^https?:\/\//i.test(q) || IPV4.test(q) || (q.includes(":") && /^[0-9a-f:]+$/i.test(q))) return "reputation";
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+\/?$/i.test(q) || /^www\./i.test(q)) return "domain";
    if (/^@?[A-Za-z0-9][A-Za-z0-9._-]{1,38}$/.test(q)) return "username";
    return null;
  }

  function go(type, value) {
    const params = new URLSearchParams({ target: value.trim(), run: "1" });
    window.location.href = `/${type}?${params.toString()}`;
  }

  /* Compact search box in the top bar (every page except the overview). */
  function bindQuick() {
    const form = document.getElementById("quick-search");
    if (!form) return;
    const input = document.getElementById("quick-q");
    const tag = document.getElementById("quick-detect");
    const label = Object.fromEntries(TYPES);
    input.addEventListener("input", () => {
      const t = detect(input.value);
      tag.hidden = !t;
      if (t) tag.textContent = label[t];
    });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const t = detect(input.value);
      if (t) go(t, input.value);
      else OSINT.toast("Enter a domain, email address, IP/URL or username.");
    });
    document.addEventListener("keydown", (e) => {
      const typing = /input|textarea|select/i.test(document.activeElement.tagName);
      if (e.key === "/" && !typing) { e.preventDefault(); OSINT.openSearch(); }
    });
  }

  /* Large search on the overview page, with type pills the user can override. */
  function bindHero() {
    const form = document.getElementById("hero-search");
    if (!form) return;
    const input = document.getElementById("hero-q");
    const pills = document.getElementById("hero-types");
    let chosen = null;      // set when the user overrides the detected type
    const buttons = TYPES.map(([key, text]) => el("button", {
      type: "button", role: "radio", "aria-checked": "false", "data-type": key, text,
      onclick: () => { chosen = key; paint(key); input.focus(); } }));
    pills.append(...buttons);

    function paint(active) {
      buttons.forEach((b) => b.setAttribute("aria-checked", String(b.dataset.type === active)));
    }
    input.addEventListener("input", () => { chosen = null; paint(detect(input.value)); });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const value = input.value.trim() || input.placeholder;
      const type = chosen || detect(value);
      if (!type) return OSINT.toast("That doesn't look like a domain, email, IP/URL or username.");
      go(type, value);
    });
    paint(detect(input.placeholder));
    document.addEventListener("keydown", (e) => {
      const typing = /input|textarea|select/i.test(document.activeElement.tagName);
      if (e.key === "/" && !typing) { e.preventDefault(); input.focus(); }
    });
  }

  document.addEventListener("DOMContentLoaded", () => { bindQuick(); bindHero(); });
  return { detect, go, TYPES };
})();
