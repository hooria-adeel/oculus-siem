import { h, icon, clear } from "../../lib/dom.js";
import { get, post, ApiError } from "../../lib/api.js";
import { empty, toast } from "../../lib/ui.js";
import { ago, dateTime, cap } from "../../lib/format.js";
import { riskMeter } from "../shared.js";
import { initials } from "../../lib/session.js";

const DEPTS = ["IT", "HR", "Finance", "Marketing", "Operations"];

export async function mount(root) {
  let users = [], dept = "", text = "";
  const tbody = h("tbody"), count = h("span", { class: "sub" });
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Department" });
  const paintChips = () => clear(chips, [["", "All"], ...DEPTS.map((d) => [d, d])].map(([v, l]) => h("button", { type: "button", class: "chip", "aria-pressed": String(dept === v), onclick: () => { dept = v; paintChips(); paint(); } }, l)));
  paintChips();

  const form = h("form", { class: "dlg-form", method: "dialog", novalidate: true });
  const err = h("p", { class: "error-text hidden", role: "alert" });
  const f = (label, name, attrs = {}) => h("div", { class: "field" }, h("label", { for: `n-${name}` }, label), h("input", { class: "input", id: `n-${name}`, name, required: true, ...attrs }));
  const dlg = h("dialog", { class: "dlg", "aria-label": "Add employee" },
    h("header", { class: "panel-head" }, h("h3", {}, "Add employee"), h("span", { class: "spacer" }), h("button", { class: "btn ghost icon-only", type: "button", "aria-label": "Close", onclick: () => dlg.close() }, icon("x"))),
    h("div", { class: "panel-body" }, form));
  form.append(f("Full name", "fullName", { autocomplete: "off" }), f("Work email", "username", { type: "email", autocomplete: "off" }),
    h("div", { class: "two" }, f("Employee ID", "employeeId", { placeholder: "OC-1234" }),
      h("div", { class: "field" }, h("label", { for: "n-role" }, "Department"), h("select", { class: "select", id: "n-role", name: "role" }, DEPTS.map((d) => h("option", { value: d }, d))))),
    f("Temporary password", "password", { type: "password", autocomplete: "new-password" }),
    h("span", { class: "hint faint" }, "At least 8 characters with upper and lower case letters, a number and a symbol."), err,
    h("div", { class: "row end" }, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Cancel"), h("button", { class: "btn primary", type: "submit" }, "Add employee")));
  form.addEventListener("submit", async (e) => {
    e.preventDefault(); err.classList.add("hidden");
    const body = Object.fromEntries(new FormData(form)); 
    try { await post("/api/employees", body); dlg.close(); form.reset(); toast(`${body.fullName} was added`); await load(); }
    catch (ex) { err.textContent = ex instanceof ApiError ? ex.message : "Something went wrong."; err.classList.remove("hidden"); }
  });

  root.append(h("div", { class: "page-head" }, count, h("span", { class: "spacer" }), chips,
    h("input", { class: "input", style: { width: "220px" }, placeholder: "Filter by name or email", "aria-label": "Filter users", oninput: (e) => { text = e.target.value.toLowerCase(); paint(); } }),
    h("button", { class: "btn primary", type: "button", onclick: () => dlg.showModal() }, icon("plus", "sm"), "Add employee")),
    h("div", { class: "panel" }, h("div", { class: "scroll" }, h("table", { class: "tbl" },
      h("thead", {}, h("tr", {}, ["Employee", "ID", "Department", "Insider risk", "Last sign-in", "Joined"].map((t) => h("th", {}, t)))), tbody))), dlg);

  function paint() {
    const list = users.filter((u) => (!dept || u.role === dept) && (!text || u.fullName.toLowerCase().includes(text) || u.username.includes(text)));
    count.textContent = `${list.length} of ${users.length} employees`;
    clear(tbody, list.length ? list.map((u) => h("tr", { class: "clickable", onclick: () => (location.hash = `#/events?user=${encodeURIComponent(u.username)}`) },
      h("td", {}, h("div", { class: "person" }, h("div", { class: "avatar" }, initials(u.fullName)), h("div", {}, h("div", { style: { fontWeight: 550 } }, u.fullName), h("div", { class: "faint", style: { fontSize: "12px" } }, u.username)))),
      h("td", { class: "mono dim" }, u.employeeId), h("td", {}, u.role), h("td", {}, riskMeter(u.riskScore)),
      h("td", { class: "dim", title: u.lastLoginAt ? dateTime(u.lastLoginAt) + " UTC" : "" }, u.lastLoginAt ? ago(u.lastLoginAt) : "never"), h("td", { class: "dim" }, dateTime(u.createdAt).slice(0, 10))))
      : h("tr", {}, h("td", { colspan: 6 }, empty("users", "No employees match"))));
  }
  async function load() { users = (await get("/api/employees")).filter((u) => u.role !== "Admin").sort((a, b) => b.riskScore - a.riskScore || a.fullName.localeCompare(b.fullName)); paint(); }
  await load();
}
