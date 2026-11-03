/**
 * List sections for the DevGuard side pane: scan log, removed extensions,
 * health check, audit log, and inventory. Pure functions (data in, HTML out).
 *
 * Built narrow-first: every row stacks vertically and dates live in day
 * dividers on the timeline rail instead of repeating in every row.
 */

const { esc, fmtTime, fmtDay, fmtClock, fmtDateTime, fmtNum, humanize, hashChip, sourceLabel } = require('./paneFormat');
const { REMOVAL_GUIDE_URL } = require('../notifier');

/** Article explaining the editor security health check settings and malware cleanup. */
const HARDEN_GUIDE_URL = 'https://yeethsecurity.com/guides/vscode-extension-malware/';

/** "What to do next ↗" link to the cleanup guide. Shown wherever a removal is listed. */
const guideLink = (cls = 'link') => `<button type="button" class="${cls}" data-url="${esc(REMOVAL_GUIDE_URL)}" title="Cleanup steps after removing a malicious extension">What to do next ↗</button>`;

/** Eyebrow summary + card body. `key` names the DOM ids for incremental updates. */
function section(key, title, count, body, open = true) {
    const badge = count === null ? '' : `<span class="count" id="count-${key}">${count}</span>`;
    return `<details data-section="${key}" ${open ? 'open' : ''}><summary class="eyebrow">${title}${badge}</summary><div class="card" id="${key}">${body}</div></details>`;
}

/** Renders items newest-first, inserting a "day" divider whenever the calendar day changes. */
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
    return r.stale ? 'warn' : 'ok';
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

const AUDIT_LABELS = {
    allowed: ['Allowed', 'warn'], unallowed: ['Allow revoked', ''], removed: ['Removed', 'bad'],
    installed: ['Installed', 'ok'], uninstalled: ['Uninstalled', ''], updated: ['Updated', ''],
    mode: ['Mode changed', ''], marketplace: ['Marketplace changed', ''],
    proxy: ['Proxy changed', ''], blocked: ['Blocked download', 'bad'],
    scanned: ['Scanned', 'ok'], hardening: ['Hardened', 'ok']
};

const HC_ICONS = {
    proxy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5.5c0 4.3 3 8.2 7 9.5 4-1.3 7-5.2 7-9.5V6z"/><path d="m9 12 2 2 4-4"/></svg>',
    tasks: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m8 10 3 2.5L8 15"/><path d="M13 15h3"/></svg>',
    updates: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M15 9.5A4 4 0 1 0 16 13"/><path d="M15 6.5v3h-3"/></svg>',
    folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="9.5" r="2.5"/><path d="M7.5 18a5 5 0 0 1 9 0"/></svg>',
    apps: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8.5" cy="8.5" r="2.5"/><circle cx="15.5" cy="8.5" r="2.5"/><circle cx="8.5" cy="15.5" r="2.5"/><circle cx="15.5" cy="15.5" r="2.5"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="16" r="1"/></svg>'
};
const ICON_OK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4 10-10"/></svg>';
const ICON_BANG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round"><path d="M12 7v6"/><path d="M12 17h.01"/></svg>';
const ICON_APPLY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg>';
const ICON_INFO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg>';

/** Hoverable info icon button that reveals a popover with details on hover only. */
function renderInfoBtn(label, bodyText) {
    return `<span class="hc__info" aria-label="More information about ${esc(label)}">${ICON_INFO}
      <span class="hc__tip" role="tooltip"><b>${esc(label)}</b> — ${esc(bodyText)}</span></span>`;
}

/** Renders the Marketplace proxy toggle switch row inside the Health check list. */
function renderProxyRow(s = {}) {
    const on = s.proxyEnabled !== false;
    const needsRestart = on && Boolean(s.proxyNeedsRestart);
    const isOk = on && !needsRestart;
    const host = s.proxyUrl ? s.proxyUrl.replace(/^https?:\/\//, '').replace(/\/_apis\/.*$/, '') : '127.0.0.1';
    let sub;
    if (!on) {
        sub = 'Action needed · Off (direct marketplace connection)';
    } else if (needsRestart) {
        sub = 'Action needed · Restart IDE to activate marketplace protection · <button type="button" class="link link--sm" data-reload="proxy">Restart now</button>';
    } else {
        sub = `Active (${esc(host)}) · injects scan data &amp; blocks threats`;
    }
    const info = renderInfoBtn(
        'Marketplace proxy',
        needsRestart
            ? 'The local marketplace proxy is configured on 127.0.0.1, but the IDE must be restarted once so marketplace traffic is routed through the proxy.'
            : 'Runs a local proxy on 127.0.0.1 that injects pkgscan.dev scan summaries into extension READMEs and blocks downloads of extensions with security advisories.'
    );
    return `<div class="hc__row ${isOk ? 'hc__row--ok' : 'hc__row--warn'}">
      <span class="hc__icon" aria-hidden="true">${HC_ICONS.proxy}</span>
      <div class="hc__body">
        <div class="hc__title-row"><label class="hc__title" for="proxy">Marketplace proxy</label>${info}</div>
        <span class="hc__sub ${isOk ? '' : 'hc__sub--warn'}">${sub}</span>
      </div>
      <label class="switch" title="Toggle local marketplace proxy"><input id="proxy" class="switch__input" type="checkbox" role="switch" aria-checked="${on ? 'true' : 'false'}" ${on ? 'checked' : ''}><span class="switch__track"></span></label>
    </div>`;
}

/**
 * Renders the Health check inside Setup: header with hover info + article link,
 * Marketplace proxy switch, and the five editor checks with two-click morphing badge.
 */
function renderHealthCheck(rows, status = {}) {
    const list = Array.isArray(rows) ? rows : [];
    const s = status || {};
    const proxyActionNeeded = s.proxyEnabled === false || Boolean(s.proxyNeedsRestart);
    const unsafe = list.filter(r => r.state === 'unsatisfied').length + (proxyActionNeeded ? 1 : 0);
    const summary = unsafe > 0 ? `<span class="hc__summary warn">${unsafe} action${unsafe === 1 ? '' : 's'} needed</span>` : '<span class="hc__summary ok">No recommended actions</span>';
    const headerInfo = renderInfoBtn('Health check', 'Checks your global editor settings against repository-based code execution and extension spoofing. Hover any ⓘ icon for details.');

    const items = list.map(row => {
        const icon = HC_ICONS[row.icon] || HC_ICONS.lock;
        const recNote = row.state === 'unavailable' ? '' : ` Recommended: ${row.recommendedLabel}.`;
        const info = renderInfoBtn(row.label, `Current: ${row.valueLabel}. ${row.detail}${recNote}${row.tooltip ? ` ${row.tooltip}` : ''}`);
        const err = row.error ? `<div class="hc__err bad">${esc(row.error)}</div>` : '';
        if (row.state === 'unsatisfied') {
            return `<div class="hc__row hc__row--warn" data-harden-arm="${esc(row.id)}">
              <span class="hc__icon" aria-hidden="true">${icon}</span>
              <div class="hc__body">
                <div class="hc__title-row"><span class="hc__title">${esc(row.label)}</span>${info}</div>
                <span class="hc__sub hc__sub--warn hc__sub--idle">${esc(row.sub || row.detail)} · Fix (${esc(row.recommendedLabel)})</span>
                <span class="hc__sub hc__sub--armed ok">Click apply icon to set ${esc(row.recommendedLabel)}</span>${err}
              </div>
              <button type="button" class="hc__badge hc__badge--warn" data-harden="${esc(row.id)}" title="Click to arm, then click again to apply (${esc(row.recommendedLabel)})" aria-label="Apply ${esc(row.label)}: ${esc(row.recommendedLabel)}">
                <span class="hc__glyph hc__glyph--warn" aria-hidden="true">${ICON_BANG}</span>
                <span class="hc__glyph hc__glyph--apply" aria-hidden="true">${ICON_APPLY}</span>
              </button>
            </div>`;
        }
        const isOk = row.state === 'satisfied';
        return `<div class="hc__row hc__row--${isOk ? 'ok' : 'na'}">
          <span class="hc__icon" aria-hidden="true">${icon}</span>
          <div class="hc__body">
            <div class="hc__title-row"><span class="hc__title">${esc(row.label)}</span>${info}</div>
            <span class="hc__sub">${esc(row.sub || row.detail)}</span>${err}
          </div>
          <span class="hc__badge ${isOk ? 'hc__badge--ok' : 'hc__badge--na'}" aria-label="${isOk ? 'Satisfied' : 'Unavailable'}">${isOk ? ICON_OK : ICON_BANG}</span>
        </div>`;
    }).join('');

    const allSafe = unsafe === 0 && list.every(r => r.state === 'satisfied');
    const footer = `<div class="hc__footer"><button type="button" class="link hc__guide" data-url="${esc(HARDEN_GUIDE_URL)}">Read the editor security guide ↗</button></div>`;
    return `<div class="field"><div class="field__row"><span class="hc__heading"><span class="field__label">Health check</span>${headerInfo}</span>${summary}</div><div class="hc" data-all-safe="${allSafe ? '1' : '0'}">${renderProxyRow(s)}${items}</div>${footer}</div>`;
}

function renderAudit(events, allowlist) {
    if (events.length === 0) return '<p class="empty">No events yet. Installs, removals, and allowlist changes will appear here.</p>';
    const allowed = new Set((allowlist || []).map(a => a.toLowerCase()));
    const seenAllowed = new Set();
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
            action = guideLink('link link--sm');
        }
        return `<li class="evt evt--${tone || 'plain'}">
          <div class="run__head"><span class="run__time">${fmtClock(e.at)}</span><span class="evt__type ${tone}">${label}</span></div>
          <div class="evt__line mono">${subject}${detail}${action}</div>
        </li>`;
    }, 'log--audit');
}

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

module.exports = { section, timeline, renderRuns, renderRemoved, renderHealthCheck, HARDEN_GUIDE_URL, renderAudit, renderInventory, AUDIT_LABELS };
