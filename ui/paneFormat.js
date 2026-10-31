/**
 * Formatting helpers for the DevGuard side pane.
 *
 * Pure functions only. No `vscode` import, so they are easy to unit test.
 * Everything user-controlled goes through `esc()` before it hits HTML.
 */

/** Escapes text for safe HTML output. */
function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** "6:31:54 PM" — time only. Dates are shown separately so rows stay short. */
function fmtTime(ms) {
    return ms ? esc(new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' })) : '—';
}

/** "6:31 PM" — time without seconds, for one-line summaries that must not wrap. */
function fmtClock(ms) {
    return ms ? esc(new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })) : '—';
}

/** "Oct 30" — short date. */
function fmtDay(ms) {
    return ms ? esc(new Date(ms).toLocaleDateString([], { month: 'short', day: 'numeric' })) : '';
}

/** "Oct 30, 6:31 PM" — for places where one line must carry both. */
function fmtDateTime(ms) {
    if (!ms) return 'never';
    return esc(new Date(ms).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }));
}

/** Thousands separator for counts: 2656 → "2,656". */
function fmtNum(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString() : esc(value);
}

/** "CREDENTIAL_THEFT" → "Credential theft". Advisory titles are machine labels. */
function humanize(label) {
    const text = String(label || '').replace(/[_-]+/g, ' ').trim().toLowerCase();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
}

function registryLabel(slug) {
    const names = { 'vscode-marketplace': 'VS Code Marketplace', 'cursor-marketplace': 'Cursor Marketplace', openvsx: 'Open VSX' };
    return names[slug] || (slug ? esc(slug) : 'Unknown');
}

/** Short names for tight spaces such as the marketplace <select>. */
function registryShort(slug) {
    const names = { 'vscode-marketplace': 'VS Code', 'cursor-marketplace': 'Cursor', openvsx: 'Open VSX' };
    return names[slug] || (slug ? esc(slug) : 'Unknown');
}

/**
 * A copyable hash "fingerprint" chip. Shows the first 8 hex chars; the full
 * SHA-256 is in `data-copy` so one click copies it.
 * @param {string} kind short label, e.g. "adv" or "inv"
 * @param {string} title tooltip explaining what was hashed
 */
function hashChip(kind, hash, title) {
    if (!hash) return `<span class="chip chip--empty"><span class="chip__k">${esc(kind)}</span>n/a</span>`;
    return `<button type="button" class="chip" data-copy="${esc(hash)}" title="${esc(title)} — click to copy">`
        + `<span class="chip__k">${esc(kind)}</span>⌗${esc(hash.slice(0, 8))}</button>`;
}

/**
 * pkgscan-style score ring: "flagged / checked" with a colored arc.
 * SVG presentation attributes are used (not inline styles) so the strict
 * CSP, which allows no `style=""` attributes, is respected.
 * @param {{flagged: number, checked: number, tone: string}} ring
 */
function ringSvg({ flagged = 0, checked = 0, tone = 'idle' }) {
    const r = 28;
    const circumference = 2 * Math.PI * r; // ≈ 175.9
    let fraction = 0;
    if (tone === 'ok' || tone === 'warn') fraction = 1;                       // full green/amber ring when clear
    else if (tone === 'bad' && checked > 0) fraction = Math.max(0.06, flagged / checked); // always-visible red arc
    else if (tone === 'busy') fraction = 0.25;                                // short arc that orbits (CSS)
    const offset = (circumference * (1 - fraction)).toFixed(2);
    const label = tone === 'idle' || tone === 'busy'
        ? `<span class="ring__big muted">—</span>`
        : `<span class="ring__big">${fmtNum(flagged)}</span><span class="ring__small">/ ${fmtNum(checked)}</span>`;
    return `<div class="ringwrap" aria-hidden="true">
      <svg class="ring" viewBox="0 0 64 64"><circle class="ring__track" cx="32" cy="32" r="${r}"/>
      <circle class="ring__arc" cx="32" cy="32" r="${r}" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${offset}"/></svg>
      <div class="ring__label">${label}</div></div>`;
}

/**
 * Turns the latest run + sync status into the headline verdict.
 * Tones: ok | bad | warn | idle | busy
 */
function computeVerdict({ status = {}, runs = [], scanning = false }) {
    if (scanning) return { tone: 'busy', title: 'Scanning…', sub: 'Checking against advisories', flagged: 0, checked: 0 };
    const last = runs[0];
    if (!last) return { tone: 'idle', title: 'Not scanned yet', sub: 'Run a scan to check your extensions', flagged: 0, checked: 0 };

    // Keep sublines short: the sidebar is ~300px wide and this must stay on one line.
    const when = fmtClock(last.at);
    const open = Math.max(0, (last.findings || 0) - (last.removed || 0));
    const plural = n => (n === 1 ? 'threat' : 'threats');

    const base = { flagged: last.findings || 0, checked: last.installed || 0, pendingReload: 0 };

    // The banner already names the problem, so sublines stay to ~30 chars.
    if (open > 0) return { ...base, tone: 'bad', title: `${open} ${plural(open)} found`, sub: `${fmtNum(last.installed)} checked · ${when}` };

    // Removed extensions stay loaded until the window reloads, so the verdict
    // stays amber (not green) and the hero shows a reload warning until then.
    // `status.pendingReload` outlives the run that removed them: later polls
    // report 0 removed, but the threat is still in memory until reload.
    const pending = Number(status.pendingReload) || 0;
    if (pending > 0) return { ...base, pendingReload: pending, tone: 'warn', title: `${pending} ${plural(pending)} removed`, sub: `reload to finish · ${when}` };
    if (last.removed > 0) return { ...base, tone: 'ok', title: `${last.removed} ${plural(last.removed)} removed`, sub: `${fmtNum(last.installed)} checked · ${when}` };
    if (last.stale || status.failureCount) return { ...base, tone: 'warn', title: 'Protected · feed stale', sub: `cached advisories · ${when}` };
    return { ...base, tone: 'ok', title: 'Protected', sub: `${fmtNum(last.installed)} extensions clear · ${when}` };
}

/**
 * Plain-English label for an extension's install source.
 * VS Code records `gallery` / `vsix` / `resource` in extensions.json; those words
 * mean little to most users, so the pane spells out where the extension came from.
 */
function sourceLabel(source) {
    const names = {
        gallery: 'From the marketplace',
        vsix: 'Installed from a VSIX file',
        resource: 'Installed from a local folder',
        unknown: 'Install source unknown'
    };
    return names[String(source || 'unknown').toLowerCase()] || esc(String(source));
}

module.exports = { esc, fmtTime, fmtClock, fmtDay, fmtDateTime, fmtNum, humanize, registryLabel, registryShort, sourceLabel, hashChip, ringSvg, computeVerdict };
