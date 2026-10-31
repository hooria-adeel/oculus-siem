import { h, icon, clear } from "../lib/dom.js";
import { get } from "../lib/api.js";
import { requireSession, signOut, initials } from "../lib/session.js";
import { time } from "../lib/format.js";
import { createLive } from "./live.js";
import { currentTheme, setTheme } from "../lib/theme.js";

const user = await requireSession("admin");
const live = createLive();

const ROUTES = {
  overview:  { title: "Overview",   icon: "layout-dashboard", group: "Monitor",     load: () => import("./pages/overview.js") },
  events:    { title: "Events",     icon: "scroll-text",      group: "Investigate", load: () => import("./pages/events.js") },
  incidents: { title: "Incidents",  icon: "siren",            group: "Investigate", load: () => import("./pages/incidents.js"), badge: true },
  rules:     { title: "Detections", icon: "radar",            group: "Detect",      load: () => import("./pages/rules.js") },
  deception: { title: "Deception",  icon: "eye",              group: "Detect",      load: () => import("./pages/deception.js") },
  users:     { title: "Users",      icon: "users",            group: "Manage",      load: () => import("./pages/users.js") },
};

const titleEl = h("h1");
const mainEl = h("main", { class: "main", id: "main" });
const badge = h("span", { class: "count hidden" });
const clockEl = h("span", { class: "clock mono" });
const liveText = h("span"), liveBtn = h("button", { type: "button", title: "Pause live updates", "aria-label": "Pause live updates" });
const liveEl = h("div", { class: "live" }, h("i", { class: "pulse" }), liveText, liveBtn);

const navLinks = {};
const groups = [...new Set(Object.values(ROUTES).map((r) => r.group))];
const nav = h("nav", { class: "nav", "aria-label": "Console" },
  h("div", { class: "brand" }, h("img", { src: "/assets/favicon.svg", alt: "" }), "Oculus", h("small", {}, "Console")),
  h("div", { class: "nav-scroll" }, groups.map((g) => h("div", { class: "nav-group" }, h("span", {}, g),
    Object.entries(ROUTES).filter(([, r]) => r.group === g).map(([key, r]) => {
      const a = h("a", { href: `#/${key}` }, icon(r.icon), r.title, r.badge && badge);
      navLinks[key] = a; return a;
    })))),
  h("div", { class: "nav-foot" }, h("div", { class: "avatar" }, initials(user.fullName)),
    h("div", { class: "who" }, h("b", {}, user.fullName), h("span", {}, "Security analyst")),
    h("button", { class: "btn ghost icon-only", type: "button", title: "Sign out", "aria-label": "Sign out", onclick: signOut }, icon("log-out"))));

const search = h("form", { class: "search", role: "search", onsubmit: (e) => { e.preventDefault(); const q = e.target.q.value.trim(); location.hash = `#/events${q ? `?q=${encodeURIComponent(q)}` : ""}`; } },
  icon("search"), h("input", { class: "input", name: "q", type: "search", placeholder: "Search events by user, IP or file", "aria-label": "Search events" }));

const themeBtn = h("button", { class: "btn ghost icon-only", type: "button", onclick: () => { setTheme(currentTheme() === "light" ? "dark" : "light"); paintTheme(); } });
function paintTheme() {
  const light = currentTheme() === "light";
  themeBtn.replaceChildren(icon(light ? "moon" : "sun"));
  themeBtn.title = themeBtn.ariaLabel = light ? "Switch to dark theme" : "Switch to light theme";
}
paintTheme();

document.getElementById("app").append(nav,
  h("header", { class: "topbar" }, titleEl, search, liveEl, themeBtn, clockEl), mainEl);

// --- live status
function paintLive({ state, paused }) {
  liveEl.className = `live ${paused ? "paused" : state === "down" ? "down" : ""}`;
  liveText.textContent = paused ? "Paused" : state === "down" ? "Reconnecting" : state === "connecting" ? "Connecting" : "Live";
  liveBtn.replaceChildren(icon(paused ? "play" : "pause", "sm"));
  liveBtn.title = liveBtn.ariaLabel = paused ? "Resume live updates" : "Pause live updates";
}
liveBtn.addEventListener("click", () => live.toggle());
live.onStatus(paintLive);
live.start();
setInterval(() => (clockEl.textContent = `${time(new Date())} UTC`), 1000); clockEl.textContent = `${time(new Date())} UTC`;

async function refreshBadge() {
  try {
    const o = await get("/api/overview", { hours: 1 });
    const n = o.kpis.openIncidents.value;
    badge.textContent = n; badge.classList.toggle("hidden", !n);
  } catch { /* nav badge is best effort */ }
}
setInterval(refreshBadge, 10000);

// --- router: #/page/param?query
let current = null, currentKey = null;
async function route() {
  const [path, qs = ""] = location.hash.replace(/^#\//, "").split("?");
  const [key = "overview", param] = path.split("/");
  const def = ROUTES[key] ?? ROUTES.overview;
  const name = ROUTES[key] ? key : "overview";
  const query = Object.fromEntries(new URLSearchParams(qs));
  if (current?.update && currentKey === name) { current.update({ param, query }); titleEl.textContent = def.title; return; }
  current?.unmount?.(); current = null; currentKey = name;
  Object.entries(navLinks).forEach(([k, a]) => { a.classList.toggle("active", k === name); k === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"); });
  titleEl.textContent = def.title; document.title = `${def.title} · Oculus Console`;
  clear(mainEl); mainEl.scrollTop = 0;
  const mod = await def.load();
  current = await mod.mount(mainEl, { user, live, refreshBadge }, { param, query });
  refreshBadge();
}
addEventListener("hashchange", route);
route();
