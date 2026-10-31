/**
 * List sections for the DevGuard side pane: scan log, removed extensions,
 * audit log, and inventory. Pure functions (data in, HTML out).
 *
 * Built narrow-first: every row stacks vertically and dates live in day
 * dividers on the timeline rail instead of repeating in every row.
 */

const { esc, fmtTime, fmtDay, fmtClock, fmtDateTime, fmtNum, humanize, hashChip, sourceLabel } = require('./paneFormat');
const { REMOVAL_GUIDE_URL } = require('../notifier');

/** "What to do next ↗" link to the cleanup guide. Shown wherever a removal is listed. */
const guideLink = (cls = 'link') => `<button type="button" class="${cls}" data-url="${esc(REMOVAL_GUIDE_URL)}" title="Cleanup steps after removing a malicious extension">What to do next ↗</button>`;

/**
 * Eyebrow summary (mono, uppercase) + card body. Mirrors pkgscan's
 * label-over-card rhythm. `key` names the DOM ids (`#<key>` for the body,
 * `#count-<key>` for the badge) that incremental updates replace.
 */
function section(key, title, count, body, open = true) {
    const badge = count === null ? '' : `<span class="count" id="count-${key}">${count}</span>`;
    return `<details data-section="${key}" ${open ? 'open' : ''}><summary class="eyebrow">${title}${badge}</summary><div class="card" id="${key}">${body}</div></details>`;
}

/**
 * Renders items newest-first, inserting a "day" divider whenever the calendar
 * day changes. Keeps rows short on narrow panes.
 */
function timeline(items, renderItem, cssClass) {
    let lastDay = null;
    const parts = [];
    for (const item of items) {
        const day = fmtDay(item.at);
        if (day !== lastDay) { parts.push(`<li class="day">${day}</li>`); lastDay = day; }
        parts.push(renderItem(item));
    }
    return `<ol class="log ${cssClass || ''}">${parts.join('')}</ol>`;
}

function runTone(r) {
    if ((r.findings || 0) - (r.removed || 0) > 0) return 'bad';
    if (r.stale) return 'warn';
    return 'ok';
}

function runSummary(r) {
    const open = (r.findings || 0) - (r.removed || 0);
    const parts = [`${fmtNum(r.installed)} checked`];
    if (r.removed > 0) parts.push(`<span class="ok">${fmtNum(r.removed)} removed</span>`);
    if (open > 0) parts.push(`<span class="bad">${fmtNum(open)} found</span>`);
    if (!r.findings) parts.push('<span class="ok">clear</span>');
    if (r.stale) parts.push('<span class="warn">stale feed</span>');
    return parts.join(' · ');
}

function renderRuns(runs) {
    if (runs.length === 0) return '<p class="empty">No scans yet. Run a scan to check your extensions.</p>';
    return timeline(runs, r => `
      <li class="run run--${runTone(r)}">
        <div class="run__head"><span class="run__time">${fmtTime(r.at)}</span><span class="tag">${esc(r.trigger)}</span></div>
        <div class="run__line">${runSummary(r)}</div>
        <div class="chips">${hashChip('adv', r.advisoryHash, `SHA-256 of the ${fmtNum(r.advisoryCount)} advisories compared against`)}${hashChip('inv', r.inventoryHash, 'SHA-256 of the installed-extension inventory')}</div>
      </li>`);
}

/** Severity pill: red for critical/high, amber for medium, slate otherwise (pkgscan finding cards). */
function sevPill(severity) {
    const level = String(severity || 'unknown').toLowerCase();
    return `<span class="sev sev--${esc(level)}">${esc(level)}</span>`;
}

function renderRemoved(removed) {
    if (removed.length === 0) return '<p class="empty">Nothing removed. Extensions that match an advisory will appear here.</p>';
    return removed.map(r => `
      <div class="item">
        <div class="item__head">${sevPill(r.severity)}<span class="item__meta">${fmtDateTime(r.at)}</span></div>
        <div class="item__id">${esc(r.id)}@${esc(r.version)}</div>
        ${r.title ? `<div class="item__title">${esc(humanize(r.title))}</div>` : ''}
        <div class="item__meta">${r.action === 'auto' ? 'Removed automatically' : 'Removed on request'}</div>
        <div class="item__actions">
          ${guideLink()}
          ${r.permalink ? `<button type="button" class="link" data-url="${esc(r.permalink)}">View report ↗</button>` : ''}
          <button type="button" class="link" data-allow="${esc(r.id)}" title="Stop flagging and removing this extension">Allow</button>
        </div>
      </div>`).join('');
}

/** Human labels and tones for audit event types. */
const AUDIT_LABELS = {
    allowed: ['Allowed', 'warn'], unallowed: ['Allow revoked', ''], removed: ['Removed', 'bad'], // "Removed" = by DevGuard; "Uninstalled" = by the user
    installed: ['Installed', 'ok'], uninstalled: ['Uninstalled', ''], updated: ['Updated', ''],
    mode: ['Mode changed', ''], marketplace: ['Marketplace changed', ''],
    scanned: ['Scanned', 'ok'] // post-install scan; tone flips to red when the entry is flagged
};

/**
 * Audit log. Allowed extensions that are still on the allowlist get a
 * "Revoke" action here, so this section replaces a separate allowlist view.
 */
function renderAudit(events, allowlist) {
    if (events.length === 0) return '<p class="empty">No events yet. Installs, removals, and allowlist changes will appear here.</p>';
    const allowed = new Set((allowlist || []).map(a => a.toLowerCase()));
    const seenAllowed = new Set(); // only the newest "allowed" entry per id gets the Revoke action
    return timeline(events, e => {
        const [label, baseTone] = AUDIT_LABELS[e.type] || [esc(e.type), ''];
        const tone = e.type === 'scanned' && e.flagged ? 'bad' : baseTone;
        const subject = e.id ? `${esc(e.id)}${e.version ? `@${esc(e.version)}` : ''}` : (e.detail ? esc(e.detail) : '');
        const detail = e.id && e.detail ? ` · ${esc(e.detail)}` : '';
        let action = '';
        if (e.type === 'allowed' && allowed.has(e.id) && !seenAllowed.has(e.id)) {
            seenAllowed.add(e.id);
            action = `<button type="button" class="link link--sm" data-unallow="${esc(e.id)}">Revoke</button>`;
        } else if (e.type === 'removed') {
            action = guideLink('link link--sm'); // cleanup guide next to every DevGuard removal
        }
        return `<li class="evt evt--${tone || 'plain'}">
          <div class="run__head"><span class="run__time">${fmtClock(e.at)}</span><span class="evt__type ${tone}">${label}</span></div>
          <div class="evt__line mono">${subject}${detail}${action}</div>
        </li>`;
    }, 'log--audit');
}

/**
 * Inventory rows are stacked so they never squeeze on narrow panes:
 * id/version, then a plain-English install source, then the SHA chip last.
 */
function renderInventory(inv) {
    if (!inv || !Array.isArray(inv.rows) || inv.rows.length === 0) return '<p class="empty">No inventory recorded yet.</p>';
    const rows = inv.rows.map(r => `
      <div class="inv">
        <div class="inv__id">${esc(r.id)} <span class="ver">${esc(r.version)}</span></div>
        <div class="inv__src">${sourceLabel(r.source)}</div>
        <div class="inv__meta">${hashChip('sha', r.hash, `SHA-256 of ${esc(r.id)}/package.json`)}</div>
      </div>`).join('');
    return `<p class="empty">Captured ${fmtDateTime(inv.at)}. Each hash is the SHA-256 of that extension's <span class="mono">package.json</span>.</p>${rows}`;
}

module.exports = { section, timeline, renderRuns, renderRemoved, renderAudit, renderInventory, AUDIT_LABELS };
