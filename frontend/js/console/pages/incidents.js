import { h, icon, clear } from "../../lib/dom.js";
import { get, post, patch } from "../../lib/api.js";
import { empty, toast, sevBadge, statusPill } from "../../lib/ui.js";
import { SEVERITIES, STATUS_LABEL, EVENT_LABEL, ago, dateTime, time, cap } from "../../lib/format.js";
import { eventDetail, EVENT_ICON, riskMeter } from "../shared.js";

const NEXT = {   // allowed one-click transitions, mirrors services/incidents.py
  open: [["investigating", "Start investigating", "play"], ["resolved", "Resolve", "check"]],
  investigating: [["resolved", "Resolve", "check"], ["open", "Back to open", "history"]],
  resolved: [["open", "Reopen", "refresh-cw"]],
};

export async function mount(root, ctx, { param }) {
  let status = "", sevs = new Set(), rows = [], dead = false, drawer = null;
  const tbody = h("tbody");
  const stat = h("div", { class: "seg", role: "group", "aria-label": "Status" });
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Severity" });
  const count = h("span", { class: "sub" });
  const tableHost = h("div", { class: "panel" });

  const paintFilters = () => {
    clear(stat, [["", "All"], ["open", "Open"], ["investigating", "Investigating"], ["resolved", "Resolved"]].map(([v, l]) =>
      h("button", { type: "button", "aria-pressed": String(status === v), onclick: () => { status = v; paintFilters(); load(); } }, l)));
    clear(chips, SEVERITIES.map((s) => h("button", { type: "button", class: `chip sev-${s}`, "aria-pressed": String(sevs.has(s)),
      onclick: () => { sevs.has(s) ? sevs.delete(s) : sevs.add(s); paintFilters(); load(); } }, cap(s))));
  };
  paintFilters();

  root.append(h("div", { class: "page-head" }, count, h("span", { class: "spacer" }), chips, stat), tableHost);

  async function load() {
    const list = await get("/api/incidents", { status, severity: [...sevs].join(","), limit: 300 });
    if (dead) return;
    rows = list;
    count.textContent = `${rows.length} incident${rows.length === 1 ? "" : "s"}`;
    if (!rows.length) return clear(tableHost, empty("circle-check", "No incidents match", "Change the filters to see more."));
    clear(tbody, rows.map((i) => {
      const tr = h("tr", { class: `clickable ${String(i.id) === param ? "selected" : ""}`, onclick: () => (location.hash = `#/incidents/${i.id}`) },
        h("td", {}, sevBadge(i.severity)), h("td", { class: "mono" }, i.ref), h("td", { title: i.title }, i.title),
        h("td", { class: "dim", title: i.subject }, i.subject), h("td", { class: "mono dim" }, i.mitreTechnique || "-"),
        h("td", { class: "mono dim" }, i.ruleId), h("td", {}, statusPill(i.status)),
        h("td", { class: "dim", title: dateTime(i.openedAt) + " UTC" }, ago(i.openedAt)));
      tr.style.setProperty("--c", `var(--sev-${i.severity})`); return tr;
    }));
    clear(tableHost, h("div", { class: "scroll", style: { maxHeight: "calc(100vh - 150px)" } }, h("table", { class: "tbl stream" },
      h("thead", {}, h("tr", {}, ["Severity", "Ref", "Title", "Subject", "Technique", "Rule", "Status", "Opened"].map((t) => h("th", {}, t)))), tbody)));
  }

  // ---- detail drawer
  async function openDrawer(id) {
    closeDrawer();
    const body = h("div", { class: "drawer-body" }, h("div", { class: "skeleton", style: { height: "120px" } }));
    const closeBtn = h("button", { class: "btn ghost icon-only", type: "button", "aria-label": "Close", onclick: () => (location.hash = "#/incidents") }, icon("x"));
    drawer = h("aside", { class: "drawer", role: "dialog", "aria-label": "Incident detail" }, h("header", { class: "drawer-head" }, h("span", { class: "muted" }, "Incident"), h("span", { class: "spacer" }), closeBtn), body);
    document.body.append(drawer); closeBtn.focus();
    try { await render(id, body); } catch (e) { clear(body, empty("octagon-alert", "Could not load this incident", e.message)); }
  }
  function closeDrawer() { drawer?.remove(); drawer = null; }

  async function render(id, body) {
    const t = await get(`/api/incidents/${id}/timeline`);
    if (dead || !drawer) return;
    const i = t.incident; let showContext = true;
    const noteBox = h("textarea", { class: "input", rows: 2, maxlength: 2000, placeholder: "Add a note for the next analyst", "aria-label": "Note" });
    const reload = () => render(id, body).then(load);

    const act = async (to) => {
      try { await patch(`/api/incidents/${i.id}`, { status: to, note: noteBox.value.trim() || undefined }); toast(`${i.ref} is now ${STATUS_LABEL[to].toLowerCase()}`); ctx.refreshBadge(); await reload(); }
      catch (e) { toast(e.message, "err"); }
    };
    const addNote = async () => {
      const text = noteBox.value.trim(); if (!text) return;
      try { await post(`/api/incidents/${i.id}/notes`, { note: text }); toast("Note added"); await reload(); } catch (e) { toast(e.message, "err"); }
    };

    const meta = [["Subject", i.subject], ["Source address", i.sourceIp || "-", true], ["Detection", i.ruleId, true],
      ["MITRE ATT&CK", i.mitreTechnique ? `${i.mitreTactic} / ${i.mitreTechnique}` : "-", true], ["Opened", `${dateTime(i.openedAt)} UTC`, true],
      ["Evidence events", String(t.stats.linkedEvents), true], i.resolvedBy ? ["Resolved by", i.resolvedBy] : null].filter(Boolean);

    const tl = h("ol", { class: "tl" });
    const paintTl = () => clear(tl, t.items.filter((x) => showContext || x.linked).map((x) => {
      const li = h("li", { class: `tl-item ${x.kind} ${x.linked ? "linked" : "context"}` });
      if (x.kind === "event") {
        const e = x.event; li.style.setProperty("--c", e.severity === "info" ? "var(--text-3)" : `var(--sev-${e.severity})`);
        li.append(h("i", { class: "tl-dot" }), h("div", { class: "tl-main" },
          h("div", { class: "tl-title" }, icon(EVENT_ICON[e.eventType] || "activity", "sm"), EVENT_LABEL[e.eventType] || e.eventType,
            x.linked ? h("span", { class: "tag-ev" }, "Evidence") : h("span", { class: "tag-ctx" }, "Context")),
          h("div", { class: "tl-sub" }, h("span", { class: "mono" }, e.username), e.sourceIp && h("span", { class: "mono" }, e.sourceIp), h("span", {}, eventDetail(e)))),
          h("time", { class: "mono faint", title: dateTime(x.time) + " UTC" }, time(x.time)));
      } else {
        const a = x.activity; li.append(h("i", { class: "tl-dot act" }), h("div", { class: "tl-main" },
          h("div", { class: "tl-title" }, icon(a.kind === "note" ? "message-square" : "flag", "sm"), a.actor === "system" ? "System" : a.actor, h("span", { class: "tag-ctx" }, cap(a.kind))),
          h("div", { class: "tl-note" }, a.message)), h("time", { class: "mono faint", title: dateTime(x.time) + " UTC" }, time(x.time)));
      }
      return li;
    }));
    paintTl();

    clear(body,
      h("div", { class: "d-title" }, h("div", { class: "d-badges" }, sevBadge(i.severity), statusPill(i.status), h("span", { class: "mono faint" }, i.ref)), h("h2", {}, i.title)),
      h("p", { class: "d-summary" }, i.summary),
      h("dl", { class: "facts" }, meta.map(([k, v, mono]) => h("div", {}, h("dt", {}, k), h("dd", { class: mono ? "mono" : "" }, v)))),
      h("section", { class: "d-actions" }, noteBox,
        h("div", { class: "row" }, NEXT[i.status].map(([to, label, ic], n) => h("button", { class: `btn ${n === 0 ? "primary" : ""}`, type: "button", onclick: () => act(to) }, icon(ic, "sm"), label)),
          h("button", { class: "btn", type: "button", onclick: addNote }, icon("message-square", "sm"), "Add note"))),
      h("section", {}, h("div", { class: "d-sec" }, h("h3", {}, "Timeline"), h("span", { class: "faint" }, `${t.stats.contextEvents} nearby ${t.stats.contextEvents === 1 ? "event" : "events"}`), h("span", { class: "spacer" }),
        h("label", { class: "check" }, h("input", { type: "checkbox", checked: true, onchange: (ev) => { showContext = ev.target.checked; paintTl(); } }), "Show surrounding activity")), tl));
  }

  const onKey = (e) => { if (e.key === "Escape" && drawer) location.hash = "#/incidents"; };
  addEventListener("keydown", onKey);
  await load();
  if (param) openDrawer(param);
  const poll = setInterval(() => !drawer && load(), 10000);
  return {
    update({ param: next }) { param = next; next ? openDrawer(next) : closeDrawer(); [...tbody.rows].forEach((tr, n) => tr.classList.toggle("selected", String(rows[n]?.id) === param)); },
    unmount() { dead = true; closeDrawer(); removeEventListener("keydown", onKey); clearInterval(poll); } };
}
