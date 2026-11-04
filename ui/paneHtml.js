/**
 * HTML for the DevGuard side pane (Activity Bar webview view).
 *
 * Pure function: data in, HTML string out. No `vscode` import, so it can be
 * unit tested. Layout, top to bottom:
 *   1. Header   — DEVGUARD eyebrow + "Secured by pkgscan.dev"
 *   2. Hero     — score ring + verdict banner
 *   3. Actions  — Run scan / Settings
 *   4. Setup    — marketplace (select), mode (segmented), feed status
 *   5. Audit log, then Setup, File threats, Scan log, Allowed extensions, Allowed files, Removed
 *
 * Built narrow-first: the pane often opens at ~190px wide.
 * Security: every user-controlled string goes through `esc()`, and the page
 * ships a strict Content-Security-Policy with a per-render nonce.
 */

const { PANE_CSS } = require('./paneStyles');
const { PANE_SCRIPT } = require('./paneScript');
const { esc, fmtClock, fmtNum, registryLabel, registryShort, ringSvg, computeVerdict } = require('./paneFormat');
const { section, renderRuns, renderExtensionThreats, renderFileThreats, renderHealthCheck, renderAudit, renderAllowedExtensions, renderAllowedFiles } = require('./paneSections');
const { REMOVAL_GUIDE_URL } = require('../notifier');
const { renderHeroThreats } = require('./paneThreats');
const { activeThreats } = require('../threats');

// Small inline icons (pkgscan buttons carry a leading icon). Stroke uses currentColor.
const ICON_RESCAN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>';
const ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4"/><path d="M12 17.5h.01"/></svg>';
const ICON_SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5.5c0 4.3 3 8.2 7 9.5 4-1.3 7-5.2 7-9.5V6z"/><path d="m9 12 2 2 4-4"/></svg>';

const MODES = [['auto', 'Auto-remove', 'removes threats automatically'], ['manual', 'Manual', 'asks before removing'], ['warn', 'Warn only', 'warns, never removes']];

function renderHeader() {
    return `<div class="header">
      <span class="eyebrow eyebrow--brand">Dev-Guard</span>
      <button type="button" id="pkgscan" class="secured" title="Advisories are provided by pkgscan.dev">${ICON_SHIELD}Secured by <b>pkgscan.dev</b></button>
    </div>`;
}

/**
 * Hero: score ring + tinted verdict banner, like pkgscan's package card.
 * When the verdict is "bad", the threats are named right under the warning
 * so the user sees WHAT was found without opening any section.
 * When it is Protected and something was removed recently, a warning under
 * the banner points at the security guide.
 */
function renderHero(v, threats = [], removalNotice = '') {
    return `<header class="hero hero--${v.tone} card">
      ${ringSvg(v)}
      <div class="hero__text"><div class="banner">${v.title}</div><div class="hero__sub">${v.sub}</div></div>
      ${v.tone === 'bad' ? renderHeroThreats(threats) : ''}
      ${v.pendingReload > 0 ? renderReloadNotice() : ''}
      ${v.tone === 'ok' && removalNotice ? renderRemovalGuideNotice(removalNotice) : ''}
    </header>`;
}

// A removal older than this is no longer "recent". The Protected banner
// stops reminding the user to read the guide.
const RECENT_REMOVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Sentence for the Protected hero when Dev-Guard removed an extension or
 * quarantined a file in the last day. A file that was put back does not count.
 * Returns '' when there is nothing to warn about.
 */
function recentRemovalNotice(audit, now = Date.now()) {
    const events = Array.isArray(audit) ? audit : [];
    let extensions = 0;
    // Latest event per file. A restore after a quarantine clears that file.
    const files = new Map();
    for (const event of events) {
        if (!event) continue;
        const at = Number(event.at) || 0;
        if (now - at > RECENT_REMOVAL_MS) continue;
        if (event.type === 'removed') {
            extensions += 1;
            continue;
        }
        if (event.type !== 'quarantined' && event.type !== 'restored') continue;
        const id = String(event.id || event.filePath || '');
        const prev = files.get(id);
        if (!prev || at >= prev.at) files.set(id, { type: event.type, at });
    }
    let fileCount = 0;
    for (const state of files.values()) {
        if (state.type === 'quarantined') fileCount += 1;
    }
    if (extensions === 0 && fileCount === 0) return '';
    const bits = [];
    if (extensions === 1) bits.push('An extension was removed');
    else if (extensions > 1) bits.push('Extensions were removed');
    if (fileCount === 1) bits.push(extensions ? 'a file was quarantined' : 'A file was quarantined');
    else if (fileCount > 1) bits.push(extensions ? 'files were quarantined' : 'Files were quarantined');
    return `${bits.join(' and ')} recently. Follow the security guide to check for anything left behind.`;
}

/** Warning under the Protected banner. The link is the cleanup guide. */
function renderRemovalGuideNotice(text) {
    return `<div class="notice notice--guide">
      <div class="notice__text">${ICON_WARN}${esc(text)}</div>
      <div class="notice__actions">
        <button type="button" class="link" data-url="${esc(REMOVAL_GUIDE_URL)}">Security guide ↗</button>
      </div>
    </div>`;
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
function renderSetup(s, lastRun, hardening = []) {
    const mode = s.removalMode || 'auto';
    const modeOptions = MODES.map(([value, label]) => `<option value="${value}" ${mode === value ? 'selected' : ''}>${label}</option>`).join('');
    const modeHint = (MODES.find(([value]) => value === mode) || MODES[0])[2];
    const feed = lastRun ? `${fmtNum(lastRun.advisoryCount)} advisories` : 'not loaded yet';
    const sync = s.failureCount
        ? `${esc(s.failureCount)} failed poll(s) · backing off`
        : `synced ${fmtClock(s.lastSyncAt)} · every 5 min`;
    // Mode sits above the Health check, and Marketplace proxy lives inside the Health check list.
    return `
      ${renderMarketplace(s)}
      <div class="field"><label class="field__label" for="mode">Mode</label>
        <select id="mode" class="select">${modeOptions}</select>
        <div class="hint">${modeHint}</div></div>
      <div class="field"><div class="field__label">Feed</div>
        <div class="field__value">${feed}</div><div class="hint">${sync}</div></div>
      ${renderHealthCheck(hardening, s)}`;
}

/**
 * Renders every dynamic fragment of the pane, keyed by the DOM id it belongs
 * in. Used for both the initial page and incremental updates, so the two can
 * never drift apart.
 * @param {{status: any, runs: any[], extensionThreats?: object[], fileThreats?: object[], audit: any[], allowlist: string[], allowedFiles?: string[], allowedFileRecords?: object[], hardening?: any[], scanning?: boolean}} data
 */
function renderParts({ status, runs = [], extensionThreats, fileThreats = [], quarantined = [], audit = [], allowlist = [], allowedFiles = [], allowedFileRecords = [], hardening = [], scanning = false }) {
    const s = status || {};
    const extThreats = Array.isArray(extensionThreats) ? extensionThreats : [];
    const threatCount = Array.isArray(fileThreats) ? fileThreats.length : 0;
    // Same list the hero names. The count has to match it, including an
    // extension that a later file-only scan did not record under `findings`.
    const liveThreats = activeThreats(runs, fileThreats, extensionThreats);
    const extCount = Array.isArray(allowlist) ? allowlist.length : 0;
    // Records carry `name (hash)`. Fall back to bare hashes from older callers.
    const fileRecords = Array.isArray(allowedFileRecords) && allowedFileRecords.length > 0
        ? allowedFileRecords
        : (Array.isArray(allowedFiles) ? allowedFiles : [...(allowedFiles || [])]).map(hash => ({ hash, label: String(hash) }));
    return {
        hero: renderHero(
            computeVerdict({ status: s, runs, fileThreats, threatCount: liveThreats.length, scanning }),
            liveThreats,
            recentRemovalNotice(audit)
        ),
        actions: renderActions(scanning),
        setup: renderSetup(s, runs[0], hardening),
        'ext-threats': renderExtensionThreats(extThreats), 'count-ext-threats': fmtNum(extThreats.length),
        'warn-ext-threats': extThreats.length > 0 ? 'Action needed' : '',
        threats: renderFileThreats(fileThreats), 'count-threats': fmtNum(threatCount),
        'warn-threats': threatCount > 0 ? 'Action needed' : '',
        runs: renderRuns(runs), 'count-runs': fmtNum(runs.length),
        'allowed-extensions': renderAllowedExtensions(allowlist), 'count-allowed-extensions': fmtNum(extCount),
        'allowed-files': renderAllowedFiles(fileRecords), 'count-allowed-files': fmtNum(fileRecords.length),
        audit: renderAudit(audit, allowlist, allowedFiles, quarantined), 'count-audit': fmtNum(audit.length)
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
<title>Dev-Guard</title><style nonce="${data.nonce}">${PANE_CSS}</style></head><body>
${renderHeader()}
<div id="hero">${p.hero}</div>
<div id="actions">${p.actions}</div>
${section('setup', 'Setup', null, p.setup)}
${section('audit', 'Audit log', p['count-audit'], p.audit)}
${section('ext-threats', 'Extension threats', p['count-ext-threats'], p['ext-threats'], true, p['warn-ext-threats'])}
${section('threats', 'File threats', p['count-threats'], p.threats, true, p['warn-threats'])}
${section('runs', 'Scan log', p['count-runs'], p.runs)}
${section('allowed-extensions', 'Allowed extensions', p['count-allowed-extensions'], p['allowed-extensions'], false)}
${section('allowed-files', 'Allowed files', p['count-allowed-files'], p['allowed-files'], false)}
<script nonce="${data.nonce}">${PANE_SCRIPT}</script></body></html>`;
}

module.exports = { esc, registryLabel, renderParts, renderPane };
