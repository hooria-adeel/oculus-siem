import { h, icon, clear } from "../../lib/dom.js";
import { get } from "../../lib/api.js";
import { empty, toast } from "../../lib/ui.js";
import { SEVERITIES, EVENT_LABEL, nf, cap, dateTime, csvCell } from "../../lib/format.js";
import { eventRow, eventDetail } from "../shared.js";

const TYPES = Object.keys(EVENT_LABEL);
const RANGES = [["1", "Last hour"], ["6", "Last 6 hours"], ["24", "Last 24 hours"], ["168", "Last 7 days"], ["", "All time"]];

export async function mount(root, { live }, { query }) {
  const f = { q: query.q || "", user: query.user || "", ip: query.ip || "", type: query.type || "", outcome: "", severity: new Set(), hours: query.hours ?? "" };
  let events = [], total = 0, tail = false, dead = false, oldest = null;
  const tbody = h("tbody"), wrap = h("div", { class: "scroll", style: { maxHeight: "calc(100vh - 205px)" } });
  const total$ = h("span", { class: "sub" });
  const more = h("button", { class: "btn", type: "button", onclick: () => load(true) }, "Load older events");

  const params = (extra = {}) => ({ q: f.q, user: f.user, ip: f.ip, type: f.type, outcome: f.outcome, severity: [...f.severity].join(","), hours: f.hours, ...extra });
  const matches = (e) => (!f.type || e.eventType === f.type) && (!f.outcome || e.outcome === f.outcome) && (!f.severity.size || f.severity.has(e.severity))
    && (!f.user || e.username.toLowerCase() === f.user.toLowerCase()) && (!f.ip || e.sourceIp === f.ip)
    && (!f.q || [e.username, e.sourceIp, e.resourceName].some((v) => v?.toLowerCase().includes(f.q.toLowerCase())));

  let timer;
  const input = (key, placeholder, w) => h("input", { class: "input", style: { width: w }, placeholder, value: f[key], "aria-label": placeholder,
    oninput: (e) => { f[key] = e.target.value.trim(); clearTimeout(timer); timer = setTimeout(() => load(), 250); } });
  const select = (key, options, label) => h("select", { class: "select", style: { width: "auto" }, "aria-label": label, onchange: (e) => { f[key] = e.target.value; load(); } },
    options.map(([v, l]) => h("option", { value: v, selected: f[key] === v }, l)));
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Severity" });
  const paintChips = () => clear(chips, SEVERITIES.map((s) => h("button", { type: "button", class: `chip sev-${s}`, "aria-pressed": String(f.severity.has(s)),
    onclick: () => { f.severity.has(s) ? f.severity.delete(s) : f.severity.add(s); paintChips(); load(); } }, cap(s))));
  paintChips();
  const tailBtn = h("button", { class: "btn", type: "button", "aria-pressed": "false", onclick: () => { tail = !tail; tailBtn.setAttribute("aria-pressed", String(tail)); tailBtn.classList.toggle("on", tail); } }, icon("radio", "sm"), "Live tail");

  root.append(
    h("div", { class: "filters" }, input("q", "Search user, IP or file", "240px"), input("user", "User email", "190px"), input("ip", "Source IP", "130px"),
      select("type", [["", "All event types"], ...TYPES.map((t) => [t, EVENT_LABEL[t]])], "Event type"),
      select("outcome", [["", "Any outcome"], ["success", "Success"], ["failure", "Failure"], ["blocked", "Blocked"]], "Outcome"),
      select("hours", RANGES, "Time range"), chips, h("span", { class: "spacer" }), tailBtn,
      h("button", { class: "btn", type: "button", onclick: exportCsv }, icon("download", "sm"), "Export CSV")),
    h("div", { class: "page-head" }, total$),
    h("div", { class: "panel" }, clear(wrap, h("table", { class: "tbl stream" },
      h("thead", {}, h("tr", {}, ["Time (UTC)", "Event", "User", "Source", "Detail"].map((t) => h("th", {}, t)))), tbody))));

  function row(e, fresh = false) {
    const tr = eventRow(e, { fresh, onClick: () => toggle(tr, e) }); tr.classList.add("clickable"); return tr;
  }
  function toggle(tr, e) {
    const next = tr.nextElementSibling;
    if (next?.classList.contains("detail")) return next.remove();
    const d = e.details || {};
    const kv = [["Event ID", e.id], ["Timestamp", `${dateTime(e.timestamp)} UTC`], ["Outcome", e.outcome], ["Severity", e.severity], ["User agent", e.userAgent || "-"], ...Object.entries(d).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)])];
    tr.after(h("tr", { class: "detail" }, h("td", { colspan: 5 }, h("dl", { class: "kv" }, kv.map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", { class: "mono" }, v)))))));
  }

  async function load(append = false) {
    const d = await get("/api/events", params({ limit: 100, before_id: append ? oldest : "" }));
    if (dead) return;
    total = d.total; if (!append) events = [];
    events = events.concat(d.events); oldest = events.at(-1)?.id ?? null;
    total$.textContent = `${nf.format(total)} matching event${total === 1 ? "" : "s"}${events.length < total ? `, showing ${nf.format(events.length)}` : ""}`;
    if (!append) clear(tbody);
    d.events.forEach((e) => tbody.append(row(e)));
    wrap.querySelector(".more")?.remove();
    if (!events.length) wrap.append(h("div", { class: "more" }, empty("search", "No events match", "Loosen a filter or widen the time range.")));
    else if (events.length < total) wrap.append(h("div", { class: "more", style: { padding: "12px", textAlign: "center" } }, more));
  }

  async function exportCsv() {
    try {
      const d = await get("/api/events", params({ limit: 500 }));
      const head = ["id", "timestamp", "event_type", "outcome", "severity", "username", "source_ip", "resource", "detail"];
      const lines = [head.join(","), ...d.events.map((e) => [e.id, e.timestamp, e.eventType, e.outcome, e.severity, e.username, e.sourceIp, e.resourceName, eventDetail(e)].map(csvCell).join(","))];
      const a = h("a", { href: URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" })), download: `oculus-events-${new Date().toISOString().slice(0, 10)}.csv` });
      document.body.append(a); a.click(); a.remove();
      toast(`Exported ${d.events.length} events${d.total > d.events.length ? ` (first 500 of ${nf.format(d.total)})` : ""}`);
    } catch (e) { toast(e.message, "err"); }
  }

  const off = live.subscribe((evs) => {
    if (!tail) return;
    evs.filter(matches).forEach((e) => { tbody.prepend(row(e, true)); events.unshift(e); total++; });
    total$.textContent = `${nf.format(total)} matching events`;
  });
  await load();
  return { unmount() { dead = true; off(); } };
}
