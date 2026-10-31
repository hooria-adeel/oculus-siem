import { h, icon, clear } from "../../lib/dom.js";
import { get } from "../../lib/api.js";
import { empty } from "../../lib/ui.js";
import { ago, dateTime } from "../../lib/format.js";
import { eventRow } from "../shared.js";

export async function mount(root) {
  const [pots, hits] = await Promise.all([get("/api/honeypots"), get("/api/events", { type: "honeypot_access", limit: 15 })]);
  root.append(
    h("div", { class: "note" }, icon("eye"), h("div", {}, h("b", {}, "Decoy files look like ordinary documents to employees."),
      " They are listed in the Shared Drive and open normally. No legitimate workflow touches them, so any access is a high-confidence signal and raises a high-severity incident immediately.")),
    h("div", { class: "grid", style: { marginTop: "12px" } },
      h("section", { class: "panel" }, h("header", { class: "panel-head" }, h("h3", {}, "Decoy files"), h("span", { class: "meta" }, `${pots.length} deployed`)),
        h("div", { class: "scroll" }, h("table", { class: "tbl" },
          h("thead", {}, h("tr", {}, ["File", "Looks like", "Opened", "People", "Last opened by", "When"].map((t, n) => h("th", { class: n === 2 || n === 3 ? "r" : "" }, t)))),
          h("tbody", {}, pots.map((p) => h("tr", {}, h("td", { class: "mono" }, p.name), h("td", { class: "dim" }, p.description),
            h("td", { class: "r num" }, p.hits || "-"), h("td", { class: "r num" }, p.uniqueUsers || "-"),
            h("td", { class: "dim" }, p.lastUser || "never"), h("td", { class: "dim", title: p.lastHitAt ? dateTime(p.lastHitAt) + " UTC" : "" }, p.lastHitAt ? ago(p.lastHitAt) : "-"))))))),
      h("section", { class: "panel" }, h("header", { class: "panel-head" }, h("h3", {}, "Recent decoy access")),
        hits.events.length ? h("div", { class: "scroll" }, h("table", { class: "tbl stream" }, h("tbody", {}, hits.events.map((e) => eventRow(e))))) : empty("shield-check", "No decoy has been opened"))));
}
