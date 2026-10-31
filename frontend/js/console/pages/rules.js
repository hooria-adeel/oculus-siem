import { h, icon } from "../../lib/dom.js";
import { get } from "../../lib/api.js";
import { sevBadge } from "../../lib/ui.js";
import { EVENT_LABEL } from "../../lib/format.js";

export async function mount(root) {
  const rules = await get("/api/rules");
  root.append(
    h("div", { class: "page-head" }, h("span", { class: "sub" }, `${rules.length} active detection rules, evaluated on every event as it is ingested`)),
    h("div", { class: "panel" }, h("div", { class: "scroll" }, h("table", { class: "tbl" },
      h("thead", {}, h("tr", {}, ["Severity", "Rule", "Name", "MITRE ATT&CK", "Triggers on", "Incidents", "Open"].map((t, n) => h("th", { class: n > 4 ? "r" : "" }, t)))),
      h("tbody", {}, rules.flatMap((r) => [
        h("tr", {}, h("td", {}, sevBadge(r.severity)), h("td", { class: "mono" }, r.id), h("td", { style: { fontWeight: 550 } }, r.name),
          h("td", {}, h("span", { class: "mono" }, r.mitreTechnique), h("span", { class: "dim" }, `  ${r.mitreTechniqueName}`)),
          h("td", { class: "dim" }, r.triggers.map((t) => EVENT_LABEL[t] || t).join(", ")),
          h("td", { class: "r num" }, r.incidents), h("td", { class: "r num" }, r.openIncidents || "-")),
        h("tr", { class: "desc" }, h("td", {}), h("td", { colspan: 6, class: "faint" }, r.description)),
      ]))))));
}
