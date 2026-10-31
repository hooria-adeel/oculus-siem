// Hand-rolled SVG charts (no library, no build step). Follows the dataviz rules: one axis, thin marks, 2px gaps
// between stacked segments, legend always present, hover tooltip, and a table view for every chart.
import { h, svg, clear, icon } from "./dom.js";
import { showTip, hideTip } from "./ui.js";
import { SEVERITIES, cap, nf, time, shortDate } from "./format.js";

const SEV_VAR = (s) => `var(--sev-${s})`;
const STACK = [...SEVERITIES].reverse();            // info at the baseline, critical on top so peaks read as danger

// Four equal gridline steps of 1, 2 or 5 x 10^k, so every tick label is a whole number.
function niceStep(max) {
  const raw = Math.max(1, max) / 4, p = 10 ** Math.floor(Math.log10(raw)), n = raw / p;
  return Math.max(1, (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p);
}

// Monotone cubic interpolation (Fritsch-Carlson): smooth like Wazuh/Kibana area charts but never overshoots the data.
function monotone(xs, ys) {
  const n = xs.length, d = [], m = [];
  for (let i = 0; i < n - 1; i++) d.push((ys[i + 1] - ys[i]) / (xs[i + 1] - xs[i] || 1));
  for (let i = 0; i < n; i++) m.push(i === 0 ? d[0] ?? 0 : i === n - 1 ? d[n - 2] : d[i - 1] * d[i] <= 0 ? 0 : (2 * d[i - 1] * d[i]) / (d[i - 1] + d[i]));
  const curves = [];
  for (let i = 0; i < n - 1; i++) {
    const hx = (xs[i + 1] - xs[i]) / 3;
    curves.push(`C${xs[i] + hx},${ys[i] + m[i] * hx} ${xs[i + 1] - hx},${ys[i + 1] - m[i + 1] * hx} ${xs[i + 1]},${ys[i + 1]}`);
  }
  return { start: `${xs[0]},${ys[0]}`, curves: curves.join(" ") };
}

export function stackedTimeline(host, { height = 300, hours = 24, kind = "bars" } = {}) {
  let data = [], showTable = false;
  const legend = h("div", { class: "legend" }, ...SEVERITIES.map((s) =>
    h("span", { class: "legend-item" }, h("i", { class: "swatch", style: { background: SEV_VAR(s) } }), cap(s))));
  const toggle = h("button", { class: "btn ghost", type: "button", onclick: () => { showTable = !showTable; draw(); } });
  const body = h("div", { class: "chart-body" });
  host.replaceChildren(h("div", { class: "chart-head" }, legend, toggle), body);

  const tipLabel = (t) => (hours > 24 ? `${shortDate(t)} ${time(t).slice(0, 5)}` : time(t).slice(0, 5));
  function bucketLabel(t) { return hours > 24 ? shortDate(t) : time(t).slice(0, 5); }

  function draw() {
    toggle.replaceChildren(icon(showTable ? "activity" : "list"), showTable ? "Chart" : "Table");
    clear(body);
    if (showTable) return body.append(tableView());
    const W = Math.max(320, body.clientWidth || host.clientWidth || 640), H = height;
    const m = { l: 34, r: 8, t: 8, b: 22 }, iw = W - m.l - m.r, ih = H - m.t - m.b;
    const totals = data.map((d) => SEVERITIES.reduce((a, s) => a + d[s], 0));
    const tick = niceStep(Math.max(1, ...totals)), max = tick * 4, step = iw / Math.max(1, data.length), bw = Math.max(2, Math.min(18, step * 0.68));
    const y = (v) => m.t + ih - (v / max) * ih;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img",
      "aria-label": `Events over time by severity, ${data.length} intervals` });
    for (let i = 0; i <= 4; i++) {
      const v = tick * i;
      root.append(svg("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: "grid" }),
        svg("text", { x: m.l - 6, y: y(v) + 3.5, class: "axis", "text-anchor": "end" }, document.createTextNode(nf.format(v))));
    }
    const every = Math.ceil(data.length / Math.max(2, Math.floor(iw / 64)));
    // Past 24h the axis marks each UTC midnight (a date) instead of repeating a date for every 6h bucket.
    const isTick = (d, i) => (hours > 24 ? new Date(d.t).getUTCHours() === 0 : i % every === 0);
    if (kind === "area" && data.length > 1) {
      const xs = data.map((_, i) => m.l + step * i + step / 2);
      let lower = data.map(() => 0);
      for (const sev of STACK) {
        const upper = lower.map((v, i) => v + data[i][sev]);
        if (upper.some((v, i) => v !== lower[i])) {
          const top = monotone(xs, upper.map(y)), bottom = monotone([...xs].reverse(), lower.map(y).reverse());
          root.append(svg("path", { d: `M${top.start} ${top.curves} L${bottom.start} ${bottom.curves} Z`, fill: SEV_VAR(sev), class: "area", "fill-opacity": 0.92 }));
        }
        lower = upper;
      }
      data.forEach((d, i) => { if (isTick(d, i)) root.append(svg("text", { x: xs[i], y: H - 6, class: "axis", "text-anchor": "middle" }, document.createTextNode(bucketLabel(d.t)))); });
      const guide = svg("line", { y1: m.t, y2: m.t + ih, class: "guide" }); guide.style.display = "none";   // CSSOM only: style attributes are blocked by the CSP
      const hit = svg("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" });
      hit.addEventListener("pointermove", (e) => {
        const box = root.getBoundingClientRect(), i = Math.max(0, Math.min(data.length - 1, Math.floor(((e.clientX - box.left) * (W / box.width) - m.l) / step)));
        guide.setAttribute("x1", xs[i]); guide.setAttribute("x2", xs[i]); guide.style.display = "";
        const d = data[i];
        showTip(e, `${tipLabel(d.t)} UTC`, [...SEVERITIES.filter((s2) => d[s2]).map((s2) => [SEV_VAR(s2), cap(s2), nf.format(d[s2])]), [null, "Total", nf.format(totals[i])]]);
      });
      hit.addEventListener("pointerleave", () => { guide.style.display = "none"; hideTip(); });
      root.append(guide, hit);
      return body.append(root);
    }
    data.forEach((d, i) => {
      const cx = m.l + step * i + step / 2;
      let acc = 0;
      for (const s of STACK) {
        if (!d[s]) continue;
        const y1 = y(acc + d[s]), y0 = y(acc);
        root.append(svg("rect", { x: cx - bw / 2, y: y1, width: bw, height: Math.max(1, y0 - y1 - 1.5), rx: 1.5, fill: SEV_VAR(s) }));
        acc += d[s];
      }
      if (isTick(d, i)) root.append(svg("text", { x: cx, y: H - 6, class: "axis", "text-anchor": "middle" }, document.createTextNode(bucketLabel(d.t))));
      const hit = svg("rect", { x: m.l + step * i, y: m.t, width: step, height: ih, fill: "transparent" });
      hit.addEventListener("pointermove", (e) => showTip(e, `${tipLabel(d.t)} UTC`,
        [...SEVERITIES.filter((s) => d[s]).map((s) => [SEV_VAR(s), cap(s), nf.format(d[s])]), [null, "Total", nf.format(totals[i])]]));
      hit.addEventListener("pointerleave", hideTip);
      root.append(hit);
    });
    body.append(root);
  }

  function tableView() {
    const rows = data.filter((d) => SEVERITIES.some((s) => d[s])).reverse();
    return h("div", { class: "chart-table" }, h("table", { class: "tbl" },
      h("thead", {}, h("tr", {}, h("th", {}, "Interval (UTC)"), ...SEVERITIES.map((s) => h("th", { class: "r" }, cap(s))))),
      h("tbody", {}, rows.map((d) => h("tr", {}, h("td", { class: "mono" }, `${shortDate(d.t)} ${time(d.t).slice(0, 5)}`),
        ...SEVERITIES.map((s) => h("td", { class: "r num" }, d[s] || "-")))))));
  }

  new ResizeObserver(() => data.length && !showTable && draw()).observe(host);
  return { update(next, hrs = hours) { data = next; hours = hrs; draw(); } };
}

/** Horizontal bars for ranked lists. rows: [{label, value, sub?}] */
export function hbars(rows, { color = "var(--series-1)", format = nf.format, onPick } = {}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return h("div", { class: "hbars" }, rows.map((r) => {
    const fill = h("i", { class: "hbar-fill" }); fill.style.width = `${(r.value / max) * 100}%`; fill.style.background = color;
    return h("div", { class: `hbar ${onPick ? "pick" : ""}`, onclick: onPick && (() => onPick(r)), tabindex: onPick ? 0 : null },
      h("span", { class: "hbar-label mono", title: r.label }, r.label),
      h("span", { class: "hbar-track" }, fill),
      h("span", { class: "hbar-val num" }, format(r.value)));
  }));
}

/** Tiny trend line for KPI tiles. */
export function sparkline(values, { w = 84, h: ht = 24 } = {}) {
  const max = Math.max(1, ...values), pts = values.map((v, i) =>
    `${(i / Math.max(1, values.length - 1)) * (w - 2) + 1},${ht - 2 - (v / max) * (ht - 4)}`);
  return svg("svg", { viewBox: `0 0 ${w} ${ht}`, width: w, height: ht, class: "spark", "aria-hidden": "true" },
    svg("polyline", { points: pts.join(" "), fill: "none", stroke: "currentColor", "stroke-width": 1.5, "stroke-linejoin": "round", "stroke-linecap": "round" }));
}


/** Donut with a legend beside it. slices: [{label, value, color, sub?}] */
export function donut(slices, { size = 150, centerLabel = "Total", onPick } = {}) {
  const total = slices.reduce((a, s) => a + s.value, 0), r = 52, C = 2 * Math.PI * r, GAP = slices.length > 1 ? 2.5 : 0;
  const root = svg("svg", { viewBox: "0 0 140 140", width: size, height: size, role: "img",
    "aria-label": `${centerLabel}: ${slices.map((s) => `${s.label} ${s.value}`).join(", ")}` });
  root.append(svg("circle", { cx: 70, cy: 70, r, fill: "none", class: "donut-track", "stroke-width": 16 }));
  let acc = 0;
  slices.forEach((sl) => {
    const len = (sl.value / total) * C;
    const arc = svg("circle", { cx: 70, cy: 70, r, fill: "none", stroke: sl.color, "stroke-width": 16, class: "slice",
      "stroke-dasharray": `${Math.max(0.5, len - GAP)} ${C}`, "stroke-dashoffset": -acc, transform: "rotate(-90 70 70)" });
    arc.addEventListener("pointermove", (e) => showTip(e, sl.label, [[sl.color, "Count", nf.format(sl.value)], [null, "Share", `${Math.round((sl.value / total) * 100)}%`]]));
    arc.addEventListener("pointerleave", hideTip);
    root.append(arc); acc += len;
  });
  root.append(svg("text", { x: 70, y: 68, class: "donut-num", "text-anchor": "middle" }, document.createTextNode(nf.format(total))),
    svg("text", { x: 70, y: 84, class: "donut-cap", "text-anchor": "middle" }, document.createTextNode(centerLabel)));
  const legend = h("ul", { class: "donut-legend" }, slices.map((sl) => h("li", { class: onPick ? "pick" : "", onclick: onPick && (() => onPick(sl)) },
    h("i", { class: "swatch", style: { background: sl.color } }), h("span", { class: "lbl", title: sl.sub ? `${sl.label} (${sl.sub})` : sl.label }, sl.label),
    h("span", { class: "num muted" }, nf.format(sl.value)))));
  return h("div", { class: "donut-wrap" }, h("div", { class: "donut" }, root), legend);
}

/** Vertical stacked bars over time, one series per entity (first series sits on the baseline). */
export function stackedBars({ buckets, series, height = 230, hours = 24 }) {
  const body = h("div", { class: "chart-body" }), legend = h("ul", { class: "donut-legend" }, series.map((s) =>
    h("li", {}, h("i", { class: "swatch", style: { background: s.color } }), h("span", { class: "lbl", title: s.label }, s.label), h("span", { class: "num muted" }, nf.format(s.total)))));
  const wrap = h("div", { class: "bars-wrap" }, body, legend);
  const label = (t) => (hours > 24 ? shortDate(t) : time(t).slice(0, 5));
  function draw() {
    clear(body);
    const W = Math.max(280, body.clientWidth || 520), H = height, m = { l: 34, r: 6, t: 8, b: 22 }, iw = W - m.l - m.r, ih = H - m.t - m.b;
    const totals = buckets.map((_, i) => series.reduce((a, s) => a + s.counts[i], 0));
    const tick = niceStep(Math.max(1, ...totals)), max = tick * 4, step = iw / buckets.length, bw = Math.max(4, Math.min(34, step * 0.7));
    const y = (v) => m.t + ih - (v / max) * ih;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img", "aria-label": "Security events per account over time" });
    for (let i = 0; i <= 4; i++) root.append(svg("line", { x1: m.l, x2: W - m.r, y1: y(tick * i), y2: y(tick * i), class: "grid" }),
      svg("text", { x: m.l - 6, y: y(tick * i) + 3.5, class: "axis", "text-anchor": "end" }, document.createTextNode(nf.format(tick * i))));
    const every = Math.ceil(buckets.length / Math.max(2, Math.floor(iw / 58)));
    buckets.forEach((t, i) => {
      const cx = m.l + step * i + step / 2; let acc = 0;
      series.forEach((s) => {
        if (!s.counts[i]) return;
        const y1 = y(acc + s.counts[i]), y0 = y(acc);
        root.append(svg("rect", { x: cx - bw / 2, y: y1, width: bw, height: Math.max(1, y0 - y1 - 1.5), rx: 1.5, fill: s.color })); acc += s.counts[i];
      });
      if (i % every === 0) root.append(svg("text", { x: cx, y: H - 6, class: "axis", "text-anchor": "middle" }, document.createTextNode(label(t))));
      const hit = svg("rect", { x: m.l + step * i, y: m.t, width: step, height: ih, fill: "transparent" });
      hit.addEventListener("pointermove", (e) => showTip(e, `${hours > 24 ? `${shortDate(t)} ${time(t).slice(0, 5)}` : label(t)} UTC`, [...series.filter((s) => s.counts[i]).map((s) => [s.color, s.label, nf.format(s.counts[i])]), [null, "Total", nf.format(totals[i])]]));
      hit.addEventListener("pointerleave", hideTip);
      root.append(hit);
    });
    body.append(root);
  }
  const ro = new ResizeObserver(draw); queueMicrotask(() => ro.observe(body));
  return wrap;
}
