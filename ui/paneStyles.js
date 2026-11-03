/**
 * CSS for the DevGuard side pane, following the pkgscan.dev design language.
 *
 * Measured from pkgscan.dev (Oct 2026):
 *   - Type: IBM Plex Sans for UI, IBM Plex Mono for labels, timestamps,
 *     hashes, and tags. Eyebrows are mono, uppercase, +0.5px tracking.
 *   - Color: slate neutrals (#0f172a ink, #64748b muted, hairline borders at
 *     rgba(15,23,42,.08)), emerald #059669 as the single brand color, red
 *     #ef4444 / #b91c1c with a 10% tint for verdicts, amber #f59e0b for medium.
 */

const PANE_CSS = `
  body {
    --sans: "IBM Plex Sans", var(--vscode-font-family), system-ui, sans-serif;
    --mono: "IBM Plex Mono", var(--vscode-editor-font-family), ui-monospace, monospace;
    --ink: #0f172a; --muted: #64748b;
    --hair: rgba(15, 23, 42, 0.08); --hair-strong: rgba(15, 23, 42, 0.14);
    --surface: rgba(255, 255, 255, 0.8); --surface-2: rgba(15, 23, 42, 0.02); --track: rgba(15, 23, 42, 0.08);
    --green: #059669; --green-deep: #047857; --green-tint: rgba(5, 150, 105, 0.1); --green-glow: rgba(5, 150, 105, 0.35);
    --red: #ef4444; --red-deep: #b91c1c; --red-tint: rgba(239, 68, 68, 0.1);
    --amber: #f59e0b; --amber-deep: #b45309; --amber-tint: rgba(245, 158, 11, 0.12);
    --focus: var(--vscode-focusBorder, #059669);
  }
  body.vscode-dark, body.vscode-high-contrast:not(.vscode-high-contrast-light) {
    --ink: var(--vscode-foreground, #e2e8f0); --muted: #94a3b8;
    --hair: rgba(255, 255, 255, 0.09); --hair-strong: rgba(255, 255, 255, 0.16);
    --surface: rgba(255, 255, 255, 0.035); --surface-2: rgba(255, 255, 255, 0.02); --track: rgba(255, 255, 255, 0.1);
    --green: #10b981; --green-deep: #34d399; --green-tint: rgba(16, 185, 129, 0.14); --green-glow: rgba(16, 185, 129, 0.3);
    --red-deep: #f87171; --red-tint: rgba(239, 68, 68, 0.14);
    --amber-deep: #fbbf24; --amber-tint: rgba(245, 158, 11, 0.16);
  }
  * { box-sizing: border-box; min-width: 0; }
  body { margin: 0; padding: 10px 10px 24px; font-family: var(--sans); font-size: 13px; line-height: 1.45; color: var(--ink); }
  button { font: inherit; color: inherit; }
  :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  .mono { font-family: var(--mono); letter-spacing: 0.02em; }
  .muted { color: var(--muted); }
  .eyebrow { font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  .eyebrow--brand { color: var(--green); }
  .card { background: var(--surface); border: 1px solid var(--hair); border-radius: 14px; padding: 10px; }

  /* ── Header & Hero ── */
  .header { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 4px 10px; margin: 0 2px 8px; }
  .secured { display: inline-flex; align-items: center; gap: 5px; padding: 0; border: 0; background: none; font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.02em; color: var(--muted); cursor: pointer; white-space: nowrap; }
  .secured b { font-weight: 600; color: var(--green); }
  .secured svg { width: 12px; height: 12px; color: var(--green); }
  .secured:hover b { text-decoration: underline; }
  .hero { display: grid; grid-template-columns: 64px 1fr; gap: 12px; align-items: center; }
  .ring { width: 64px; height: 64px; transform: rotate(-90deg); }
  .ring circle { fill: none; stroke-width: 7; }
  .ring__track { stroke: var(--track); }
  .ring__arc { stroke: var(--muted); stroke-linecap: round; transition: stroke-dashoffset .4s ease; }
  .hero--ok .ring__arc { stroke: var(--green); } .hero--bad .ring__arc { stroke: var(--red); } .hero--warn .ring__arc { stroke: var(--amber); }
  .hero--busy .ring__arc { animation: orbit 1.2s linear infinite; transform-origin: 50% 50%; }
  .ring__label { position: absolute; inset: 0; display: flex; align-items: baseline; justify-content: center; padding-top: 22px; font-family: var(--mono); line-height: 1; }
  .ring__big { font-size: 18px; font-weight: 700; } .ring__small { font-size: 11px; color: var(--muted); margin-left: 2px; }
  .hero--bad .ring__big { color: var(--red); } .hero--ok .ring__big { color: var(--green); } .hero--warn .ring__big { color: var(--amber-deep); }
  .ringwrap { position: relative; width: 64px; height: 64px; }
  .banner { display: inline-block; max-width: 100%; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 13px; line-height: 1.35; background: var(--surface-2); color: var(--ink); border: 1px solid var(--hair); }
  .hero--ok .banner { background: var(--green-tint); color: var(--green-deep); border-color: transparent; }
  .hero--bad .banner { background: var(--red-tint); color: var(--red-deep); border-color: transparent; }
  .hero--warn .banner { background: var(--amber-tint); color: var(--amber-deep); border-color: transparent; }
  .hero__sub { margin-top: 6px; font-family: var(--mono); font-size: 11.5px; color: var(--muted); letter-spacing: 0.02em; }
  .notice { grid-column: 1 / -1; margin-top: 2px; padding: 10px 12px; border-radius: 10px; background: var(--amber-tint); border: 1px solid rgba(245, 158, 11, 0.35); }
  .notice__text { display: flex; align-items: flex-start; gap: 7px; font-size: 12px; line-height: 1.4; color: var(--ink); }
  .notice__text svg { flex: 0 0 auto; width: 15px; height: 15px; margin-top: 1px; color: var(--amber-deep); }
  .notice__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 12px; margin-top: 8px; }

  /* ── Buttons & Setup Controls ── */
  .actions { display: flex; gap: 8px; margin: 10px 0 14px; }
  .btn { flex: 1; display: inline-flex; justify-content: center; align-items: center; gap: 7px; height: 34px; padding: 0 14px; border-radius: 24px; border: 0; cursor: pointer; font-weight: 600; font-size: 13px; white-space: nowrap; background: var(--green); color: #fff; box-shadow: 0 4px 14px -3px var(--green-glow); }
  .btn:hover { background: var(--green-deep); color: #fff; }
  .btn svg { width: 14px; height: 14px; }
  .btn--secondary { flex: 0 0 auto; border-radius: 10px; background: transparent; color: var(--ink); border: 1px solid var(--hair-strong); box-shadow: none; }
  .btn--secondary:hover { background: var(--surface-2); color: var(--ink); }
  .btn--warn { flex: 0 0 auto; height: 28px; padding: 0 12px; font-size: 12px; background: var(--amber); color: rgba(0,0,0,.87); box-shadow: none; }
  .btn--warn:hover { background: var(--amber-deep); color: rgba(0,0,0,.87); }
  .btn:disabled { opacity: .6; cursor: progress; }
  .spinner { width: 13px; height: 13px; border-radius: 50%; border: 2px solid rgba(255,255,255,.45); border-right-color: #fff; animation: spin .8s linear infinite; }
  .field { padding: 8px 0; border-bottom: 1px solid var(--hair); }
  .field:first-child { padding-top: 0; } .field:last-child { padding-bottom: 0; border-bottom: 0; }
  .field__label { display: block; font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
  .field__value { font-weight: 600; }
  .hint { margin-top: 4px; font-size: 11.5px; color: var(--muted); overflow-wrap: anywhere; }
  .select, .input { width: 100%; height: 28px; padding: 0 8px; border-radius: 8px; border: 1px solid var(--hair-strong); background: var(--vscode-dropdown-background, transparent); color: var(--ink); font: inherit; }
  .select { font-weight: 600; cursor: pointer; }
  .input { margin-top: 6px; font-family: var(--mono); font-size: 11.5px; background: var(--vscode-input-background, transparent); }
  .input::placeholder { color: var(--muted); }
  .select:hover, .input:hover { border-color: var(--green); }
  .input:focus { outline: none; border-color: var(--green); }
  .is-hidden { display: none; }
  .field__row { position: relative; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .field__row .field__label { margin-bottom: 0; }
  .switch { position: relative; display: inline-flex; align-items: center; cursor: pointer; flex: 0 0 auto; }
  .switch__input { position: absolute; opacity: 0; width: 0; height: 0; }
  .switch__track { width: 34px; height: 19px; border-radius: 999px; background: var(--track); border: 1px solid var(--hair-strong); position: relative; transition: background .15s ease, border-color .15s ease; }
  .switch__track::after { content: ""; position: absolute; top: 2px; left: 2px; width: 13px; height: 13px; border-radius: 50%; background: var(--muted); transition: transform .15s ease, background .15s ease; }
  .switch__input:checked + .switch__track { background: var(--green); border-color: var(--green); }
  .switch__input:checked + .switch__track::after { transform: translateX(15px); background: #fff; }
  .switch__input:focus-visible + .switch__track { outline: 2px solid var(--focus); outline-offset: 2px; }

  /* ── Google Security Checkup list + hover info popover + morphing apply badge ── */
  .hc { display: flex; flex-direction: column; margin-top: 6px; }
  .hc__heading { display: inline-flex; align-items: center; gap: 5px; }
  .hc__summary { font-family: var(--mono); font-size: 10.5px; }
  .hc__row { position: relative; width: 100%; display: grid; grid-template-columns: 20px 1fr auto; align-items: center; gap: 10px; padding: 8px 4px; border: 0; border-bottom: 1px solid var(--hair); background: transparent; text-align: left; }
  .hc__row:last-child { border-bottom: 0; padding-bottom: 2px; }
  .hc__row[data-harden-arm], .hc__title[for="proxy"] { cursor: pointer; }
  .hc__row[data-harden-arm] { border-radius: 8px; }
  .hc__row[data-harden-arm]:hover { background: var(--amber-tint); }
  .hc__row.is-armed { background: var(--green-tint); }
  .hc__icon { display: inline-flex; width: 18px; height: 18px; color: var(--muted); }
  .hc__row--warn .hc__icon { color: var(--amber-deep); }
  .hc__row.is-armed .hc__icon { color: var(--green); }
  .hc__body { display: flex; flex-direction: column; min-width: 0; }
  .hc__title-row { display: inline-flex; align-items: center; gap: 5px; }
  .hc__title { font-weight: 600; font-size: 12.5px; color: var(--ink); line-height: 1.3; }
  .hc__sub { font-size: 11px; color: var(--muted); line-height: 1.35; margin-top: 1px; }
  .hc__sub--warn { color: var(--amber-deep); font-weight: 500; }
  .hc__sub--armed { display: none; }
  .hc__row.is-armed .hc__sub--idle { display: none; }
  .hc__row.is-armed .hc__sub--armed { display: block; }
  .hc__err { font-size: 11px; margin-top: 2px; }
  .hc__badge { position: relative; display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; padding: 0; border: 0; border-radius: 50%; flex: 0 0 auto; }
  .hc__badge svg { width: 11px; height: 11px; }
  .hc__badge--ok { background: var(--green); color: #fff; }
  .hc__badge--na { background: var(--track); color: var(--muted); }
  /* Cycle/morph animation from amber warning (!) to green apply arrow (→) on arm. */
  .hc__badge--warn { background: var(--amber); color: #fff; cursor: pointer; transition: background .35s cubic-bezier(.4, 0, .2, 1), transform .45s cubic-bezier(.34, 1.56, .64, 1), box-shadow .35s ease; }
  .hc__glyph { position: absolute; display: inline-flex; align-items: center; justify-content: center; transition: transform .4s cubic-bezier(.4, 0, .2, 1), opacity .25s ease; }
  .hc__glyph--warn { opacity: 1; transform: rotate(0deg) scale(1); }
  .hc__glyph--apply { opacity: 0; transform: rotate(-180deg) scale(0.3); }
  .hc__row.is-armed .hc__badge--warn { background: var(--green); box-shadow: 0 0 0 3px var(--green-tint); transform: rotate(360deg) scale(1.1); }
  .hc__row.is-armed .hc__glyph--warn { opacity: 0; transform: rotate(180deg) scale(0.3); }
  .hc__row.is-armed .hc__glyph--apply { opacity: 1; transform: rotate(0deg) scale(1); }
  /* Info button is static so .hc__tip anchors to .hc__row / .field__row (left:0; right:0) and never overflows right. */
  .hc__info { position: static; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; margin: -2px 0; color: var(--muted); cursor: help; flex: 0 0 auto; }
  .hc__info svg { width: 13px; height: 13px; }
  .hc__info:hover { color: var(--green); }
  .hc__tip { display: none; position: absolute; z-index: 30; left: 0; right: 0; top: 26px; padding: 8px 10px; border-radius: 10px; border: 1px solid var(--hair-strong); background: var(--vscode-editorHoverWidget-background, #fff); color: var(--ink); font-family: var(--sans); font-size: 11.5px; font-weight: 400; line-height: 1.45; text-transform: none; letter-spacing: normal; box-shadow: 0 10px 28px rgba(15, 23, 42, .18); user-select: text; cursor: auto; }
  .field__row .hc__tip { top: calc(100% + 4px); }
  .hc__tip::before { content: ""; position: absolute; left: 0; right: 0; top: -14px; height: 14px; }
  .hc__tip b { font-weight: 600; }
  .hc__info:hover .hc__tip { display: block; }
  body.vscode-dark .hc__tip, body.vscode-high-contrast:not(.vscode-high-contrast-light) .hc__tip { background: var(--vscode-editorHoverWidget-background, #1e293b); box-shadow: 0 10px 28px rgba(0, 0, 0, .5); }
  .hc__footer { margin-top: 6px; padding-top: 4px; display: flex; align-items: center; justify-content: flex-end; }
  .hc__guide { font-size: 11.5px; }

  /* ── Sections, Timeline, Removed, Audit, Inventory ── */
  details { margin-top: 12px; }
  summary { list-style: none; display: flex; align-items: center; gap: 6px; padding: 0 2px 8px; cursor: pointer; user-select: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: ""; width: 5px; height: 5px; border-right: 1.5px solid var(--muted); border-bottom: 1.5px solid var(--muted); transform: rotate(-45deg); margin-right: 2px; transition: transform .12s ease; }
  details[open] > summary::before { transform: rotate(45deg); }
  summary .count { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .empty { margin: 0; color: var(--muted); font-size: 12.5px; }
  .log { position: relative; margin: 0; padding: 0 0 0 16px; list-style: none; }
  .log::before { content: ""; position: absolute; left: 3px; top: 8px; bottom: 8px; width: 1px; background: var(--hair-strong); }
  .run, .evt { position: relative; padding: 2px 0 12px; }
  .evt { padding-bottom: 10px; }
  .run:last-child, .evt:last-child { padding-bottom: 0; }
  .run::before, .evt::before { content: ""; position: absolute; left: -16px; top: 7px; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); box-shadow: 0 0 0 3px var(--vscode-sideBar-background, #fff); }
  .run--ok::before, .evt--ok::before { background: var(--green); }
  .run--bad::before, .evt--bad::before { background: var(--red); }
  .run--warn::before, .evt--warn::before { background: var(--amber); }
  .day { position: relative; margin: 0 0 6px; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  .day::before { content: ""; position: absolute; left: -17px; top: 5px; width: 9px; height: 1px; background: var(--hair-strong); }
  .run + .day, .evt + .day { margin-top: 10px; }
  .run__head { display: flex; align-items: baseline; gap: 6px; }
  .run__time { font-family: var(--mono); font-weight: 600; font-size: 12.5px; white-space: nowrap; }
  .tag { margin-left: auto; font-family: var(--mono); font-size: 10px; font-weight: 700; letter-spacing: 0.05em; padding: 1px 6px; border-radius: 6px; border: 1px solid var(--hair-strong); color: var(--muted); white-space: nowrap; }
  .run__line { margin-top: 2px; font-size: 12.5px; color: var(--muted); }
  .ok { color: var(--green); font-weight: 600; } .bad { color: var(--red); font-weight: 600; } .warn { color: var(--amber-deep); font-weight: 600; }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
  .chip { display: inline-flex; align-items: center; gap: 5px; height: 20px; padding: 0 7px; border: 1px solid var(--hair); border-radius: 6px; background: var(--surface-2); font-family: var(--mono); font-size: 11px; color: var(--muted); cursor: copy; }
  .chip:hover { border-color: var(--green); color: var(--green); }
  .chip--empty { cursor: default; }
  .chip__k { font-size: 9px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
  .chip.copied { border-color: var(--green); color: var(--green); background: var(--green-tint); }
  .item { padding: 10px 12px; border: 1px solid var(--hair); border-radius: 12px; background: var(--surface-2); margin-top: 8px; }
  .item:first-child { margin-top: 0; }
  .item__head { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; }
  .sev { font-family: var(--mono); font-size: 10.5px; font-weight: 700; letter-spacing: 0.05em; padding: 1px 7px; border-radius: 6px; background: var(--muted); color: #fff; }
  .sev--critical, .sev--high { background: var(--red); } .sev--medium { background: var(--amber); color: rgba(0,0,0,.87); }
  .item__id { font-family: var(--mono); font-weight: 600; font-size: 12.5px; overflow-wrap: anywhere; margin-top: 6px; }
  .item__title { font-weight: 600; margin-top: 2px; }
  .item__meta { margin-top: 2px; font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .item__actions { display: flex; flex-wrap: wrap; gap: 4px 14px; margin-top: 8px; }
  .link { background: none; border: 0; padding: 0; color: var(--green); font-weight: 600; font-size: 12.5px; cursor: pointer; }
  .link:hover { color: var(--green-deep); text-decoration: underline; }
  .link--sm { font-size: 11px; margin-left: 8px; }
  .evt__type { margin-left: auto; font-size: 11px; font-weight: 600; color: var(--muted); text-align: right; }
  .evt__line { margin-top: 1px; font-size: 11px; color: var(--ink); overflow-wrap: anywhere; }
  .inv { padding: 7px 0; border-bottom: 1px solid var(--hair); }
  .inv:last-child { border-bottom: 0; padding-bottom: 0; }
  .inv__id { font-size: 12.5px; font-weight: 600; overflow-wrap: anywhere; }
  .inv__id .ver { font-family: var(--mono); color: var(--muted); font-size: 11px; font-weight: 400; white-space: nowrap; }
  .inv__src { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .inv__meta { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; margin-top: 4px; }
  @media (max-width: 239px) {
    .hero { grid-template-columns: 1fr; gap: 8px; }
    .ringwrap { margin: 0 auto; }
    .hero__text { text-align: center; }
    .actions { flex-direction: column; }
    .btn--secondary { flex: 1; }
    .evt__type { margin-left: 0; text-align: left; }
    .run__head { flex-wrap: wrap; }
  }
  @keyframes orbit { to { transform: rotate(360deg); } }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .hero--busy .ring__arc, .spinner { animation: none; } .ring__arc, summary::before { transition: none; } }
`;

module.exports = { PANE_CSS };
