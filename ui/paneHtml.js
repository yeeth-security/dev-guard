/**
 * HTML for the DevGuard side pane (Activity Bar webview view).
 *
 * Pure function: data in, HTML string out. No `vscode` import, so it can be
 * unit tested. Layout, top to bottom:
 *   1. Header   — DEVGUARD eyebrow + "Secured by pkgscan.dev"
 *   2. Hero     — score ring + verdict banner
 *   3. Actions  — Run scan / Settings
 *   4. Setup    — marketplace (select), mode (segmented), feed status
 *   5. Scan log, Removed, Audit log, Inventory (see paneSections.js)
 *
 * Built narrow-first: the pane often opens at ~190px wide.
 * Security: every user-controlled string goes through `esc()`, and the page
 * ships a strict Content-Security-Policy with a per-render nonce.
 */

const { PANE_CSS } = require('./paneStyles');
const { PANE_SCRIPT } = require('./paneScript');
const { esc, fmtClock, fmtNum, registryLabel, registryShort, ringSvg, computeVerdict } = require('./paneFormat');
const { section, renderRuns, renderRemoved, renderAudit, renderInventory } = require('./paneSections');
const { REMOVAL_GUIDE_URL } = require('../notifier');

// Small inline icons (pkgscan buttons carry a leading icon). Stroke uses currentColor.
const ICON_RESCAN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>';
const ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4"/><path d="M12 17.5h.01"/></svg>';
const ICON_SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5.5c0 4.3 3 8.2 7 9.5 4-1.3 7-5.2 7-9.5V6z"/><path d="m9 12 2 2 4-4"/></svg>';

const MODES = [['auto', 'Auto-remove', 'removes threats automatically'], ['prompt', 'Prompt', 'asks before removing'], ['warn', 'Warn only', 'warns, never removes']];

function renderHeader() {
    return `<div class="header">
      <span class="eyebrow eyebrow--brand">DevGuard</span>
      <button type="button" id="pkgscan" class="secured" title="Advisories are provided by pkgscan.dev">${ICON_SHIELD}Secured by <b>pkgscan.dev</b></button>
    </div>`;
}

/** Hero: score ring + tinted verdict banner, like pkgscan's package card. */
function renderHero(v) {
    return `<header class="hero hero--${v.tone} card">
      ${ringSvg(v)}
      <div class="hero__text"><div class="banner">${v.title}</div><div class="hero__sub">${v.sub}</div></div>
      ${v.pendingReload > 0 ? renderReloadNotice() : ''}
    </header>`;
}

/**
 * Warning shown under the verdict while a removed extension is still loaded.
 * Reload actually unloads it; the guide covers what else to check.
 */
function renderReloadNotice() {
    return `<div class="notice">
      <div class="notice__text">${ICON_WARN}Removed extensions stay loaded until you reload.</div>
      <div class="notice__actions">
        <button type="button" id="reload" class="btn btn--warn">Reload window</button>
        <button type="button" class="link" data-url="${esc(REMOVAL_GUIDE_URL)}">What to do next ↗</button>
      </div>
    </div>`;
}

function renderActions(scanning) {
    const label = scanning ? '<span class="spinner"></span>Scanning…' : `${ICON_RESCAN}Run scan`;
    return `<div class="actions">
      <button type="button" id="scan" class="btn" ${scanning ? 'disabled' : ''}>${label}</button>
      <button type="button" id="settings" class="btn btn--secondary">Settings</button></div>`;
}

/** Marketplace field: Default (detected) or Custom, which reveals a URL box. */
function renderMarketplace(s) {
    const custom = s.marketplaceMode === 'custom';
    const url = s.marketplaceUrl || '';
    let hint;
    if (!custom) hint = `${registryLabel(s.detectedRegistry)} · via ${esc(s.registryMethod || 'unknown')}`;
    else if (!url) hint = 'Enter your gallery URL to apply';
    else if (s.registry) hint = `Matches ${registryLabel(s.registry)}`;
    else hint = 'Unknown host · checking all marketplaces';
    return `
      <div class="field"><label class="field__label" for="marketplace">Marketplace</label>
        <select id="marketplace" class="select">
          <option value="" ${custom ? '' : 'selected'}>Default · ${registryShort(s.detectedRegistry)}</option>
          <option value="custom" ${custom ? 'selected' : ''}>Custom URL</option>
        </select>
        <input id="marketplaceUrl" class="input ${custom ? '' : 'is-hidden'}" type="url" value="${esc(url)}" placeholder="https://…/gallery" spellcheck="false">
        <div class="hint">${hint}</div></div>`;
}

/** Setup card: stacked label-over-control blocks (works at any width). */
function renderSetup(s, lastRun) {
    const mode = s.removalMode || 'auto';
    const modeOptions = MODES.map(([value, label]) => `<option value="${value}" ${mode === value ? 'selected' : ''}>${label}</option>`).join('');
    const modeHint = (MODES.find(([value]) => value === mode) || MODES[0])[2];
    const feed = lastRun ? `${fmtNum(lastRun.advisoryCount)} advisories` : 'not loaded yet';
    const sync = s.failureCount
        ? `${esc(s.failureCount)} failed poll(s) · backing off`
        : `synced ${fmtClock(s.lastSyncAt)} · every 5 min`;
    return `
      ${renderMarketplace(s)}
      <div class="field"><label class="field__label" for="mode">Mode</label>
        <select id="mode" class="select">${modeOptions}</select>
        <div class="hint">${modeHint}</div></div>
      <div class="field"><div class="field__label">Feed</div>
        <div class="field__value">${feed}</div><div class="hint">${sync}</div></div>`;
}

/**
 * Renders every dynamic fragment of the pane, keyed by the DOM id it belongs
 * in. Used for both the initial page and incremental updates, so the two can
 * never drift apart.
 * @param {{status: any, runs: any[], inventory: any, removed: any[], audit: any[], allowlist: string[], scanning?: boolean}} data
 */
function renderParts({ status, runs = [], inventory, removed = [], audit = [], allowlist = [], scanning = false }) {
    const s = status || {};
    const invCount = inventory && Array.isArray(inventory.rows) ? inventory.rows.length : 0;
    return {
        hero: renderHero(computeVerdict({ status: s, runs, scanning })),
        actions: renderActions(scanning),
        setup: renderSetup(s, runs[0]),
        runs: renderRuns(runs), 'count-runs': fmtNum(runs.length),
        removed: renderRemoved(removed), 'count-removed': fmtNum(removed.length),
        audit: renderAudit(audit, allowlist), 'count-audit': fmtNum(audit.length),
        inventory: renderInventory(inventory), 'count-inventory': fmtNum(invCount)
    };
}

/**
 * Full page. Only used for the first render; later changes arrive as
 * `update` messages (see paneScript.js) so the page is never reloaded.
 * @param {{nonce: string} & Parameters<typeof renderParts>[0]} data
 */
function renderPane(data) {
    const p = renderParts(data);
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${data.nonce}'; script-src 'nonce-${data.nonce}';">
<title>DevGuard</title><style nonce="${data.nonce}">${PANE_CSS}</style></head><body>
${renderHeader()}
<div id="hero">${p.hero}</div>
<div id="actions">${p.actions}</div>
${section('setup', 'Setup', null, p.setup)}
${section('runs', 'Scan log', p['count-runs'], p.runs)}
${section('removed', 'Removed', p['count-removed'], p.removed)}
${section('audit', 'Audit log', p['count-audit'], p.audit, false)}
${section('inventory', 'Inventory', p['count-inventory'], p.inventory, false)}
<script nonce="${data.nonce}">${PANE_SCRIPT}</script></body></html>`;
}

module.exports = { esc, registryLabel, renderParts, renderPane };
