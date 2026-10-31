import { h, icon } from "./dom.js";
import { SEV_ICON, STATUS_LABEL, cap } from "./format.js";

export const sevBadge = (sev) => h("span", { class: `sev sev-${sev}` }, icon(SEV_ICON[sev] || "circle"), cap(sev));
export const statusPill = (st) => h("span", { class: `pill ${st}` }, STATUS_LABEL[st] || st);

let host;
export function toast(message, kind = "ok") {
  host ??= document.body.appendChild(h("div", { class: "toast-host", role: "status", "aria-live": "polite" }));
  const t = h("div", { class: `toast ${kind === "err" ? "err" : ""}` }, message);
  host.append(t);
  setTimeout(() => t.remove(), 4200);
}

export function empty(iconName, title, hint) {
  return h("div", { class: "empty" }, icon(iconName), h("strong", {}, title), hint && h("span", {}, hint));
}

// Shared tooltip used by charts.
let tip;
export function showTip(evt, head, rows) {
  tip ??= document.body.appendChild(h("div", { class: "tooltip hidden", role: "tooltip" }));
  tip.replaceChildren(h("div", { class: "t-head" }, head), ...rows.map(([color, label, value]) =>
    h("div", { class: "t-row" }, h("span", {}, color && h("i", { class: "dot", style: { color } }), label), h("span", { class: "num" }, value))));
  tip.classList.remove("hidden");
  const r = tip.getBoundingClientRect();
  tip.style.left = Math.min(evt.clientX + 14, innerWidth - r.width - 8) + "px";
  tip.style.top = Math.min(evt.clientY + 14, innerHeight - r.height - 8) + "px";
}
export const hideTip = () => tip?.classList.add("hidden");
