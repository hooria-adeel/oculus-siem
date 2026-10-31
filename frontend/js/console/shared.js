import { h, icon } from "../lib/dom.js";
import { sevBadge, statusPill } from "../lib/ui.js";
import { EVENT_LABEL, time, ago } from "../lib/format.js";

export const EVENT_ICON = {
  login_success: "log-out", login_failed: "key-round", login_blocked: "ban", logout: "log-out",
  access_granted: "file-text", access_denied: "lock", honeypot_access: "eye",
};
EVENT_ICON.login_success = "user-check";

export function eventDetail(e) {
  switch (e.eventType) {
    case "login_failed": return e.username?.includes("@") ? "Password rejected" : "Unknown account";
    case "login_blocked": return "Locked out: too many failures";
    case "login_success": return "Signed in";
    case "logout": return "Signed out";
    case "access_denied": return `${e.resourceName ?? "-"} (outside role)`;
    default: return e.resourceName ?? "";
  }
}

export function eventRow(e, { fresh = false, onClick } = {}) {
  const tr = h("tr", { class: `${fresh ? "fresh" : ""} ${onClick ? "clickable" : ""}`, onclick: onClick });
  tr.style.setProperty("--c", e.severity === "info" ? "transparent" : `var(--sev-${e.severity})`);
  tr.append(
    h("td", { class: "mono dim" }, time(e.timestamp)),
    h("td", {}, h("span", { class: "ev" }, icon(EVENT_ICON[e.eventType] || "activity", "sm"), EVENT_LABEL[e.eventType] || e.eventType)),
    h("td", { title: e.username }, e.username),
    h("td", { class: "mono dim" }, e.sourceIp || "-"),
    h("td", { class: "dim", title: eventDetail(e) }, eventDetail(e)));
  return tr;
}

export function incidentListRow(i, onOpen) {
  const row = h("div", { class: "irow", role: "button", tabindex: 0, onclick: () => onOpen(i) },
    h("i", { class: "gutter" }),
    h("div", { style: { minWidth: 0 } },
      h("div", { class: "t", title: i.title }, i.title),
      h("div", { class: "s" }, sevBadge(i.severity), h("span", { class: "mono" }, i.ref), h("span", {}, i.ruleId))),
    h("div", { class: "r" }, ago(i.openedAt)));
  row.style.setProperty("--c", `var(--sev-${i.severity})`);
  row.addEventListener("keydown", (e) => { if (e.key === "Enter") onOpen(i); });
  return row;
}

export const riskColor = (n) => (n > 70 ? "var(--sev-critical)" : n >= 40 ? "var(--sev-high)" : "var(--sev-info)");
export function riskMeter(score) {
  const fill = h("i"); fill.style.width = `${Math.min(100, score)}%`; fill.style.background = riskColor(score);
  return h("span", { class: "risk" }, h("span", { class: "riskbar", title: `Risk ${score} / 100` }, fill), h("span", { class: "num" }, score));
}

export function panel(title, { meta, actions, flush = false, cls = "" } = {}, ...body) {
  return h("section", { class: `panel ${cls}` },
    h("header", { class: "panel-head" }, h("h3", {}, title), meta && h("span", { class: "meta" }, meta), h("span", { class: "spacer" }), actions),
    h("div", { class: `panel-body ${flush ? "flush" : ""}` }, body));
}
export { statusPill, sevBadge };
