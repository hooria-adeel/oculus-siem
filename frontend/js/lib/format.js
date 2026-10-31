// Time is shown in UTC in the console (analysts correlate across time zones) and local in the workspace.
const two = (n) => String(n).padStart(2, "0");
const parse = (iso) => (iso instanceof Date ? iso : new Date(iso));

export function time(iso, utc = true) {
  const d = parse(iso);
  return utc ? `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}` : `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}
export function dateTime(iso, utc = true) {
  const d = parse(iso);
  const y = utc ? d.getUTCFullYear() : d.getFullYear(), m = (utc ? d.getUTCMonth() : d.getMonth()) + 1, day = utc ? d.getUTCDate() : d.getDate();
  return `${y}-${two(m)}-${two(day)} ${time(d, utc)}`;
}
export function shortDate(iso) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(parse(iso));
}
export function ago(iso, now = Date.now()) {
  const s = Math.max(0, Math.round((now - parse(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const nf = new Intl.NumberFormat("en-US");

export const EVENT_LABEL = {
  login_success: "Sign-in", login_failed: "Failed sign-in", login_blocked: "Sign-in blocked", logout: "Sign-out",
  access_granted: "File opened", access_denied: "Access denied", honeypot_access: "Decoy opened",
};
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEV_ICON = { critical: "octagon-alert", high: "triangle-alert", medium: "circle-alert", low: "info", info: "circle" };
export const STATUS_LABEL = { open: "Open", investigating: "Investigating", resolved: "Resolved" };
export const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

export function csvCell(v) {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;            // neutralise spreadsheet formula injection
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}
