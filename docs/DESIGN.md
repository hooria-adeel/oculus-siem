# Design notes

Oculus ships two interfaces on one design system. They are deliberately *not* the same product visually,
because the two audiences do different work.

| | **Oculus Workspace** (employees) | **Oculus Console** (security analysts) |
|---|---|---|
| Job | Open the files I need for my job | Find out what is happening, decide, act |
| Feels like | Everyday office / cloud-drive software | A SOC console (Splunk, Wazuh, Elastic Security) |
| Theme | Light, calm, generous spacing | Dark, dense, 13px base, tabular data |
| What it must never do | Hint that anything is monitored or that decoys exist | Hide evidence or make a decision for the analyst |

## Tokens

Console (dark)

| Token | Hex | Use |
|---|---|---|
| canvas | `#0d1116` | page background |
| panel | `#141a21` | cards, tables |
| raised | `#19212b` | hover, drawers, menus |
| rule | `#222c38` | 1px dividers |
| text / text-2 / text-3 | `#d6dce4` / `#9aa7b6` / `#75828f` | primary / secondary / tertiary ink |
| accent | `#3bb3a6` | focus, selection, primary action only (never data) |

Severity (ordered, always paired with an icon and a label, never colour alone)

| critical | high | medium | low | info |
|---|---|---|---|---|
| `#d03b3b` | `#ec835a` | `#f4d03f` | `#3987e5` | `#7d8793` |

Validated with the dataviz validator against the panel colour: CVD separation, normal-vision separation and
3:1 contrast all pass. The lightness-band check fails by design: severity is an ordered status ramp, not a
set of interchangeable categories, so lightness is allowed to rise toward yellow.

Workspace (light): canvas `#f3f5f8`, surface `#ffffff`, rule `#e1e5eb`, ink `#1f2733`, accent `#1d5fd1`.

## Type

Inter (variable) for interface text; JetBrains Mono only for things that are literally machine data
(timestamps, IP addresses, incident refs, rule ids), always with tabular figures. Both are self-hosted.

## Principles

1. **Density is information.** The console shows more rows, not bigger rows. 28px table rows, one-line cells.
2. **One memorable thing.** The live event stream: new rows slide in under a severity gutter, and the stream
   can be paused so an analyst can read it. Everything else stays quiet.
3. **Structure carries meaning.** A left gutter colour = severity. Borders separate regions. Nothing is a card
   just because it can be.
4. **No emoji, no gradients, no decorative motion.** Motion only answers an action (drawer opens) or flags
   something new (a row arrives).
5. **No `innerHTML`.** The UI is built with a small DOM helper, so event data (usernames, user agents, file
   names) can never become markup. The CSP therefore needs no `unsafe-inline`.
6. **Deception stays invisible.** Employees see decoys as ordinary files and never see a risk score.

## Assets

Inter (SIL OFL), JetBrains Mono (SIL OFL) and Lucide icons (ISC) are vendored under `frontend/assets/` with their
licences. Nothing loads from a third-party host.

## Console themes (dark and light)

The Console ships dark by default and has a sun/moon toggle in the top bar. The choice is stored in `localStorage`
(`oculus-theme`) and applied by `js/theme-init.js` before first paint, so there is no flash. If storage is blocked the
Console simply stays dark.

Light is a separate set of tokens with the same density, not an inversion. Severity colours were re-stepped per surface and
validated with the dataviz palette validator:

| Severity | Dark panel | Light panel |
|---|---|---|
| Critical | `#d03b3b` | `#c62f2f` |
| High | `#c98500` | `#b87500` |
| Medium | `#3987e5` | `#2a78d6` |
| Low | `#199e70` | `#00855a` |
| Info | `#7d8793` | `#6a7584` |

Dark passes every check. Light passes lightness, chroma, normal-vision and 3:1 contrast; its colour-blind separation sits in
the 6-8 band, so colour never works alone: every severity has an icon and a word, stacked segments have a gap, the chart has a
table view, and tooltips list values.

## Login page

A split screen that shows the two products: the Console world (dark, a slow radar sweep around the Oculus eye) next to the
Workspace world (light form). The animation is CSS only and stops under `prefers-reduced-motion`. In demo mode
(`FLASK_ENV=development` or `OCULUS_DEMO_MODE=1`) it lists one-click sign-ins for the fictional seeded accounts, served by
`GET /api/demo-accounts`. That endpoint returns nothing outside demo mode and only lists accounts that exist in the database.
**Never enable demo mode in production.**
