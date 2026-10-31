// Runs before first paint (classic script, no module) so a saved light theme never flashes dark.
try { var t = localStorage.getItem("oculus-theme"); if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t); } catch (e) { /* storage blocked: default theme */ }
