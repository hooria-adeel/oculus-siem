import { h, icon, clear, append } from "/js/lib/dom.js";
import { get, post } from "/js/lib/api.js";
import { requireSession, signOut, initials } from "/js/lib/session.js";
import { ago } from "/js/lib/format.js";
import { empty, toast } from "/js/lib/ui.js";

const user = await requireSession("employee");

// ---- file helpers
const EXT = { pdf: ["file-text", "ft-pdf"], xlsx: ["file-spreadsheet", "ft-sheet"], csv: ["file-spreadsheet", "ft-sheet"], docx: ["file-text", "ft-doc"],
  txt: ["file-text", "ft-doc"], sql: ["file-code", "ft-code"], config: ["file-code", "ft-code"], conf: ["file-code", "ft-code"], zip: ["file-archive", "ft-other"] };
const typeOf = (name) => EXT[name.split(".").pop().toLowerCase()] || ["file", "ft-other"];
const isCode = (name) => ["sql", "config", "conf", "csv"].includes(name.split(".").pop().toLowerCase());
const size = (kb) => (kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`);
const modified = (iso) => { const d = new Date(iso), t = new Date(); return d.toDateString() === t.toDateString() ? d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric", year: d.getFullYear() === t.getFullYear() ? undefined : "numeric" }); };
const fileIcon = (name, cls = "") => { const [i, c] = typeOf(name); return icon(i, `${c} ${cls}`); };

let files = [], recent = [], sort = { key: "modifiedAt", dir: -1 }, query = "";
const main = h("main", { class: "ws-main", id: "main" });
const nav = h("nav", { class: "ws-nav", "aria-label": "Folders" });
const searchInput = h("input", { type: "search", placeholder: "Search in Workspace", "aria-label": "Search in Workspace",
  oninput: (e) => { query = e.target.value.trim().toLowerCase(); render(); } });

// ---- shell
const menu = h("div", { class: "ws-menu hidden" }, h("div", { class: "who" }, h("div", { class: "ws-avatar" }, initials(user.fullName)),
  h("div", {}, h("b", {}, user.fullName), h("span", {}, user.username), h("span", {}, `${user.role} · ${user.employeeId}`))),
  h("button", { class: "btn", type: "button", onclick: signOut }, icon("log-out", "sm"), "Sign out"));
const avatar = h("button", { class: "ws-avatar", type: "button", "aria-label": "Account", "aria-haspopup": "true", onclick: () => menu.classList.toggle("hidden") }, initials(user.fullName));
document.addEventListener("click", (e) => { if (!menu.contains(e.target) && e.target !== avatar) menu.classList.add("hidden"); });
document.getElementById("app").append(
  h("header", { class: "ws-top" }, h("div", { class: "ws-brand" }, h("img", { src: "/assets/mark-light.svg", alt: "" }), h("span", {}, h("b", {}, "Oculus"), " Workspace")),
    h("div", { class: "ws-search", role: "search" }, icon("search", "lg"), searchInput), h("div", { class: "ws-user" }, avatar, menu)),
  nav, main);

// ---- routing: #/home | #/recent | #/folder/<name>
const route = () => { const [, key = "home", ...rest] = location.hash.split("/"); return { key, arg: decodeURIComponent(rest.join("/")) }; };
const folders = () => { const names = [...new Set(files.map((f) => f.folder))]; return [user.role, "Shared Drive", ...names.filter((n) => n !== user.role && n !== "Shared Drive").sort()].filter((n) => names.includes(n)); };

function paintNav() {
  const r = route();
  const link = (href, ic, label, active, extra) => h("a", { href, class: active ? "active" : "", "aria-current": active ? "page" : null }, icon(ic), label, extra);
  clear(nav, link("#/home", "home", "Home", r.key === "home" && !query), link("#/recent", "clock", "Recent", r.key === "recent"), h("h4", {}, "Folders"),
    folders().map((f) => link(`#/folder/${encodeURIComponent(f)}`, f === "Shared Drive" ? "users-round" : "folder", f === user.role ? `${f} (my team)` : f, r.key === "folder" && r.arg === f)));
}

// ---- views
function sortHead(label, key) {
  const on = sort.key === key;
  return h("th", { onclick: () => { sort = { key, dir: on ? -sort.dir : 1 }; render(); }, "aria-sort": on ? (sort.dir === 1 ? "ascending" : "descending") : "none" },
    label, on && icon(sort.dir === 1 ? "arrow-up" : "arrow-down"));
}
function fileTable(list) {
  if (!list.length) return empty("search", query ? `No results for "${query}"` : "This folder is empty", query ? "Check the spelling or try a different search." : "");
  const sorted = [...list].sort((a, b) => (a[sort.key] > b[sort.key] ? 1 : -1) * sort.dir);
  return h("table", { class: "tbl" }, h("thead", {}, h("tr", {}, sortHead("Name", "name"), sortHead("Location", "folder"), sortHead("Modified", "modifiedAt"), sortHead("Size", "sizeKb"))),
    h("tbody", {}, sorted.map((f) => h("tr", { tabindex: 0, onclick: () => openFile(f), onkeydown: (e) => e.key === "Enter" && openFile(f) },
      h("td", {}, h("span", { class: "fname" }, fileIcon(f.name, "lg"), f.name, f.category === "restricted" && icon("lock", "sm lock"))),
      h("td", {}, f.folder), h("td", {}, modified(f.modifiedAt)), h("td", {}, size(f.sizeKb))))));
}
const card = (f, sub) => h("button", { class: "fcard", type: "button", onclick: () => openFile(f) },
  h("div", { class: "thumb" }, fileIcon(f.name)), h("div", { class: "cap" }, fileIcon(f.name), h("div", {}, h("b", { title: f.name }, f.name), h("span", {}, sub))));

function render() {
  paintNav();
  const r = route(), by = Object.fromEntries(files.map((f) => [f.name, f]));
  clear(main);
  if (query) {
    const hits = files.filter((f) => f.name.toLowerCase().includes(query) || f.description?.toLowerCase().includes(query));
    return append(main, [h("h1", {}, "Search results"), fileTable(hits)]);
  }
  if (r.key === "folder") {
    return append(main, [h("div", { class: "crumb" }, h("a", { href: "#/home" }, "Workspace"), icon("chevron-right"), h("span", {}, r.arg)), fileTable(files.filter((f) => f.folder === r.arg))]);
  }
  if (r.key === "recent") {
    const list = recent.map((x) => by[x.name] && { ...by[x.name], openedAt: x.openedAt }).filter(Boolean);
    return append(main, [h("h1", {}, "Recent"), list.length ? h("div", { class: "cards" }, list.map((f) => card(f, `Opened ${ago(f.openedAt)}`)))
      : empty("clock", "Nothing here yet", "Files you open will show up here.")]);
  }
  const hour = new Date().getHours(), greet = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  const suggested = recent.slice(0, 4).map((x) => by[x.name] && { ...by[x.name], openedAt: x.openedAt }).filter(Boolean);
  append(main, [h("h1", {}, `${greet}, ${user.fullName.split(" ")[0]}`),
    suggested.length ? [h("h2", {}, "Suggested for you"), h("div", { class: "cards" }, suggested.map((f) => card(f, `You opened this ${ago(f.openedAt)}`)))] : null,
    h("h2", {}, "Folders"), h("div", { class: "folders" }, folders().map((n) => h("button", { class: "folder", type: "button", onclick: () => (location.hash = `#/folder/${encodeURIComponent(n)}`) },
      icon(n === "Shared Drive" ? "users-round" : "folder"), n === user.role ? `${n} (my team)` : n, h("small", {}, `${files.filter((f) => f.folder === n).length} files`)))),
    h("h2", {}, "All files"), fileTable(files)]);
}

// ---- file viewer
const viewer = h("dialog", { class: "viewer", "aria-label": "File viewer" });
viewer.addEventListener("click", (e) => { if (e.target === viewer) viewer.close(); });
document.body.append(viewer);

async function openFile(f) {
  const closeBtn = h("button", { class: "btn ghost icon-only", type: "button", "aria-label": "Close", onclick: () => viewer.close() }, icon("x"));
  const body = h("div", { class: "viewer-body" }, h("div", { class: "skeleton", style: { width: "min(720px,100%)", height: "60%" } }));
  clear(viewer, h("header", { class: "viewer-head" }, fileIcon(f.name, "lg"), h("b", {}, f.name), h("span", { class: "spacer" }), closeBtn), body);
  viewer.showModal();
  try {
    const res = await post("/api/access", { resourceName: f.name });
    if (res.authorized) clear(body, h("article", { class: `page ${isCode(f.name) ? "code" : ""}` }, res.content));
    else clear(body, h("div", { class: "denied" }, icon("lock"), h("h3", {}, "You need access"), h("p", { class: "muted" }, "You don't have permission to open this file. Ask the owner of the folder if you need access."),
      res.warning && h("div", { class: "warn" }, res.warning)));
    if (res.authorized) { recent = (await get("/api/my/recent")); if (route().key !== "folder") render(); }
  } catch (e) { viewer.close(); toast(e.message, "err"); }
}

files = await get("/api/resources");
recent = await get("/api/my/recent");
addEventListener("hashchange", () => { searchInput.value = ""; query = ""; render(); });
render();
