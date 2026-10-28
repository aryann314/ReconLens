/* theme-init.js - runs in <head> before the page paints, so the chosen
   light/dark theme is applied without a flash. (A separate file because the
   Content-Security-Policy forbids inline scripts.) The design is dark by
   default; a light theme is used only when the visitor picked it. */
(function () {
  try {
    var t = localStorage.getItem("osint-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable - keep the default dark theme */ }
})();
