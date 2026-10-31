// Overview: modelled on the Wazuh "Threat Hunting" dashboard. A KPI strip, two chart rows, an alerts table, then the live stream.
import { h, icon, clear } from "../../lib/dom.js";
import { get } from "../../lib/api.js";
import { stackedTimeline, hbars, donut, stackedBars } from "../../lib/charts.js";
import { empty, sevBadge, statusPill } from "../../lib/ui.js";
import { nf, time, shortDate } from "../../lib/format.js";
import { panel, eventRow, riskMeter } from "../shared.js";
import { initials } from "../../lib/session.js";

const RANGES = [[1, "1h"], [6, "6h"], [24, "24h"], [168, "7d"]];
const SLOTS = [1, 2, 3, 4, 5];

/** Colour follows the entity, not its rank: a key keeps its slot while it stays in the list, and a new key takes a free one. */
function colorAssigner() {
  const slot = new Map();
  return (keys) => {
    const used = new Set(keys.filter((k) => slot.has(k)).map((k) => slot.get(k)));
    keys.forEach((k) => {
      if (slot.has(k)) return;
      const free = SLOTS.find((s) => !used.has(s)) ?? 1;
      slot.set(k, free); used.add(free);
    });
    return (k) => (k == null ? "var(--cat-other)" : `var(--cat-${slot.get(k)})`);
  };
}

function kcell({ label, iconName, value, tone, delta, unit, href }) {
  const d = delta == null ? null : delta;
  const val = h("div", { class: `kvalue ${tone || ""}` }, nf.format(value));
  const sub = h("div", { class: "kdelta" }, d == null ? "" : d === 0 ? `No change vs prior ${unit}` : [icon(d > 0 ? "arrow-up-right" : "arrow-down-right", "sm"), `${d > 0 ? "+" : ""}${nf.format(d)} vs prior ${unit}`]);
  return h(href ? "a" : "div", { class: "kcell", href }, h("div", { class: "klabel" }, icon(iconName, "sm"), label), val, sub);
}

export async function mount(root, { live }) {
  let hours = 24, loading = false, lastLoad = 0, dead = false;
  const techColor = colorAssigner(), acctColor = colorAssigner();
  const strip = h("section", { class: "panel kstrip" });
  const areaHost = h("div"), area = stackedTimeline(areaHost, { hours, kind: "area", height: 270 });
  const mitre = h("div", { class: "fill" }), accounts = h("div", { class: "fill" }), acctBars = h("div", { class: "fill" }), alerts = h("tbody"), alertsEmpty = h("div");
  const stream = h("tbody"), sources = h("div"), people = h("div");
  const rangeLabel = h("span", { class: "sub" });
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Time range" });
  const paintSeg = () => clear(seg, RANGES.map(([hrs, label]) =>
    h("button", { type: "button", "aria-pressed": String(hrs === hours), onclick: () => { hours = hrs; paintSeg(); load(true); } }, label)));
  paintSeg();

  const alertsTable = h("table", { class: "tbl alerts" },
    h("thead", {}, h("tr", {}, ["Time (UTC)", "Subject", "Technique", "Tactic", "Description", "Level", "Status", "Rule"].map((t) => h("th", {}, t)))), alerts);

  root.append(
    h("div", { class: "page-head" }, rangeLabel, h("span", { class: "spacer" }), seg),
    strip,
    h("div", { class: "grid g-2-1" },
      panel("Alerts evolution", { meta: "events by severity" }, areaHost),
      panel("MITRE ATT&CK", { meta: "techniques by evidence", actions: h("a", { href: "#/rules", class: "btn ghost" }, "Detections") }, mitre)),
    h("div", { class: "grid g-1-2" },
      panel("Top 5 accounts", { meta: "security events" }, accounts),
      panel("Alerts evolution: top 5 accounts", {}, acctBars)),
    panel("Security alerts", { meta: "latest incidents", actions: h("a", { href: "#/incidents", class: "btn ghost" }, "All incidents"), flush: true, cls: "mb" },
      h("div", { class: "scroll" }, alertsTable), alertsEmpty),
    h("div", { class: "grid g-3" },
      panel("Live event stream", { meta: "newest first", actions: h("a", { href: "#/events", class: "btn ghost" }, "Explore"), flush: true },
        h("div", { class: "stream-wrap scroll" }, h("table", { class: "tbl stream" },
          h("thead", {}, h("tr", {}, ["Time (UTC)", "Event", "User", "Source", "Detail"].map((t) => h("th", {}, t)))), stream))),
      h("div", { style: { display: "grid", gap: "12px", alignContent: "start" } },
        panel("Failed sign-ins by source", { meta: "address" }, sources),
        panel("Highest insider risk", { meta: "score / 100", flush: true }, people))));

  async function load(force = false) {
    if (loading || dead || (!force && Date.now() - lastLoad < 4000)) return;
    loading = true;
    try {
      const [o, inc] = await Promise.all([get("/api/overview", { hours }), get("/api/incidents", { limit: 8 })]);
      if (dead) return;
      lastLoad = Date.now();
      const unit = hours === 168 ? "7d" : `${hours}h`, k = o.kpis, by = k.openIncidents.bySeverity;
      rangeLabel.textContent = `Last ${RANGES.find((r) => r[0] === hours)[1]}`;

      clear(strip,
        kcell({ label: "Total events", iconName: "activity", value: k.events.value, delta: k.events.value - k.events.previous, unit }),
        kcell({ label: "Critical and high incidents", iconName: "siren", value: (by.critical || 0) + (by.high || 0), tone: "t-critical", href: "#/incidents" }),
        kcell({ label: "Authentication failure", iconName: "key-round", value: k.failedLogins.value, tone: "t-high", delta: k.failedLogins.value - k.failedLogins.previous, unit, href: "#/events?type=login_failed" }),
        kcell({ label: "Authentication success", iconName: "user-check", value: k.successfulLogins.value, tone: "t-good", delta: k.successfulLogins.value - k.successfulLogins.previous, unit }),
        kcell({ label: "Decoy files opened", iconName: "eye", value: k.honeypotHits.value, delta: k.honeypotHits.value - k.honeypotHits.previous, unit, href: "#/deception" }));

      area.update(o.timeline, hours);

      // MITRE donut: top 5 techniques, the rest folded into "Other" (never a 6th hue).
      const techs = o.techniques, topT = techs.slice(0, 5), restN = techs.slice(5).reduce((a, t) => a + t.events, 0);
      const tc = techColor(topT.map((t) => t.id));
      clear(mitre, topT.length ? donut([...topT.map((t) => ({ label: t.name.replace(/^Brute Force: /, ""), sub: `${t.id} ${t.name}`, value: t.events, color: tc(t.id) })),
        ...(restN ? [{ label: "Other techniques", value: restN, color: "var(--cat-other)" }] : [])], { centerLabel: "Evidence events", size: 200 })
        : empty("radar", "No techniques observed", "No incidents opened in this period."));

      const aa = o.accountActivity, ac = acctColor(aa.accounts.filter((a) => a.username).map((a) => a.username));
      const series = aa.accounts.map((a) => ({ ...a, color: ac(a.username) }));
      clear(accounts, series.length ? donut(series.map((a) => ({ label: a.label, sub: a.username, value: a.total, color: a.color })), { centerLabel: "Events" })
        : empty("shield-check", "No security events", "in this period"));
      clear(acctBars, series.length ? stackedBars({ buckets: aa.buckets, series, hours }) : empty("activity", "Nothing to plot", "No security events in this period."));

      clear(alerts, inc.map((i) => {
        const tr = h("tr", { class: "clickable", tabindex: 0, onclick: () => (location.hash = `#/incidents/${i.id}`) },
          h("td", { class: "mono dim" }, `${shortDate(i.openedAt)} ${time(i.openedAt)}`), h("td", { title: i.subject, class: "c-subject" }, i.subject),
          h("td", { class: "c-tech", title: i.mitreTechniqueName || "" }, h("span", { class: "mono tech-id" }, i.mitreTechnique || "-"), " ", h("span", { class: "dim" }, i.mitreTechniqueName || "")),
          h("td", { class: "dim" }, i.mitreTactic || "-"), h("td", { title: i.title, class: "c-desc" }, i.title),
          h("td", {}, sevBadge(i.severity)), h("td", {}, statusPill(i.status)), h("td", { class: "mono dim" }, i.ruleId));
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter") tr.click(); });
        return tr;
      }));
      clear(alertsEmpty, inc.length ? [] : empty("circle-check", "No alerts yet", "Detections are running."));

      clear(sources, o.topSources.length ? hbars(o.topSources.map((s) => ({ label: s.ip, value: s.failures })), { color: "var(--sev-high)", onPick: (r) => (location.hash = `#/events?ip=${r.label}`) }) : empty("shield-check", "No failed sign-ins", "in this period"));
      clear(people, o.riskUsers.length ? o.riskUsers.map((u) => h("div", { class: "urow" },
        h("div", { class: "avatar" }, initials(u.fullName)), h("div", {}, h("div", { class: "n" }, u.fullName), h("div", { class: "d" }, u.role)), riskMeter(u.riskScore))) : empty("user-check", "No elevated risk"));
    } finally { loading = false; }
  }

  const initial = await get("/api/events", { limit: 40 });
  initial.events.forEach((e) => stream.append(eventRow(e, { onClick: () => (location.hash = `#/events?q=${encodeURIComponent(e.username)}`) })));
  await load(true);

  const off = live.subscribe((events) => {
    for (const e of events) stream.prepend(eventRow(e, { fresh: true, onClick: () => (location.hash = `#/events?q=${encodeURIComponent(e.username)}`) }));
    while (stream.rows.length > 60) stream.lastChild.remove();
    load();
  });
  const poll = setInterval(() => load(), 15000);
  return { unmount() { dead = true; off(); clearInterval(poll); } };
}
