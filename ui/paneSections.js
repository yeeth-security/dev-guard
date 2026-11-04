/**
 * List sections for the DevGuard side pane: extension threats, file threats,
 * scan log, allowed extensions, allowed files, health check, and audit log.
 * Pure functions (data in, HTML out).
 *
 * Built narrow-first: every row stacks vertically and dates live in day
 * dividers on the timeline rail instead of repeating in every row.
 */

const { esc, fmtTime, fmtDay, fmtClock, fmtNum, humanize, hashChip } = require('./paneFormat');
const { REMOVAL_GUIDE_URL } = require('../notifier');
const { renderRunFound } = require('./paneThreats');

/** Article explaining the editor security health check settings and malware cleanup. */
const HARDEN_GUIDE_URL = 'https://yeethsecurity.com/guides/vscode-extension-malware/';

/** "What to do next ↗" link to the cleanup guide. Shown on extension threats and removal audit entries. */
const guideLink = (cls = 'link') => `<button type="button" class="${cls}" data-url="${esc(REMOVAL_GUIDE_URL)}" title="Cleanup steps after removing a malicious extension">What to do next ↗</button>`;

/**
 * Eyebrow summary + card body. `key` names the DOM ids for incremental updates.
 * Rows inside the card carry `data-row`. The pane script shows 5 at a time
 * and adds a "Show more" button (see paneScript.js).
 */
function section(key, title, count, body, open = true, warn = '') {
    const badge = count === null ? '' : `<span class="count" id="count-${key}">${count}</span>`;
    // Updated on its own so a later scan can show or clear the header warning
    // without rebuilding the whole dropdown.
    const flag = `<span class="section-warn" id="warn-${key}">${esc(warn)}</span>`;
    return `<details data-section="${key}" ${open ? 'open' : ''}><summary class="eyebrow">${title}${flag}${badge}</summary><div class="card" id="${key}">${body}</div><div class="more" id="more-${key}"></div></details>`;
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
    const openExt = Math.max(0, (r.findings || 0) - (r.removed || 0));
    const openFiles = Number(r.fileFindings) || 0;
    if (openExt + openFiles > 0) return 'bad';
    return r.stale ? 'warn' : 'ok';
}

function runSummary(r) {
    const open = Math.max(0, (r.findings || 0) - (r.removed || 0));
    const fileFindings = Number(r.fileFindings) || 0;
    const parts = [`${fmtNum(r.installed)} checked`];
    if (r.removed > 0) parts.push(`<span class="ok">${fmtNum(r.removed)} removed</span>`);
    if (open > 0) parts.push(`<span class="bad">${fmtNum(open)} found</span>`);
    if (fileFindings > 0) parts.push(`<span class="bad">${fmtNum(fileFindings)} file threat${fileFindings === 1 ? '' : 's'}</span>`);
    if (!r.findings && !fileFindings) parts.push('<span class="ok">clear</span>');
    if (r.stale) parts.push('<span class="warn">stale feed</span>');
    return parts.join(' · ');
}

function renderRuns(runs) {
    if (runs.length === 0) return '<p class="empty">No scans yet. Run a scan to check your extensions.</p>';
    return timeline(runs, r => `
      <li class="run run--${runTone(r)}" data-row>
        <div class="run__head"><span class="run__time">${fmtTime(r.at)}</span><span class="tag">${esc(r.trigger)}</span></div>
        <div class="run__line">${runSummary(r)}</div>
        ${renderRunFound(r.details)}
        <div class="chips">${hashChip('adv', r.advisoryHash, `SHA-256 of the ${fmtNum(r.advisoryCount)} advisories compared against`)}${hashChip('inv', r.inventoryHash, 'SHA-256 of the installed-extension inventory')}</div>
      </li>`);
}

function sevPill(severity) {
    const level = String(severity || 'unknown').toLowerCase();
    return `<span class="sev sev--${esc(level)}">${esc(level)}</span>`;
}

/**
 * Live flagged extensions the user can still act on.
 * Uninstall removes it, Allow stops future flags, View report opens the advisory.
 * Already-removed extensions are not listed here; those stay in the audit log.
 */
function renderExtensionThreats(threats = []) {
    const list = Array.isArray(threats) ? threats : [];
    if (list.length === 0) return '<p class="empty">No extension threats. Flagged extensions that are still installed will appear here.</p>';
    return list.map(t => {
        // Same key the hero eye uses, so a click can flash this exact card.
        const key = `${t.id}@${t.version || 'unknown'}`;
        return `
      <div class="item" data-row data-threat-key="${esc(key)}">
        <div class="item__head">${sevPill(t.severity)}</div>
        <div class="item__id">${esc(key)}</div>
        ${t.title ? `<div class="item__title">${esc(humanize(t.title))}</div>` : ''}
        <div class="item__actions">
          <button type="button" class="link" data-remove-extension="${esc(t.id)}" title="Uninstall this extension">Uninstall</button>
          ${t.permalink ? `<button type="button" class="link" data-url="${esc(t.permalink)}">View report ↗</button>` : ''}
          <button type="button" class="link" data-allow="${esc(t.id)}" title="Stop flagging and removing this extension">Allow</button>
          ${guideLink()}
        </div>
      </div>`;
    }).join('');
}

/**
 * Turns "N unaddressed file threat(s)" into a button that opens File threats.
 * Used on the Auto-run row, whose row click applies a setting, so only the
 * threat words should navigate.
 */
function unaddressedControl(sub) {
    const text = String(sub || '');
    const match = text.match(/^(.*?)(\d+ unaddressed file threats?)(.*)$/);
    if (!match) return esc(text);
    const phrase = `<button type="button" class="link link--inline" data-open-section="threats">${esc(match[2])}</button>`;
    return `${esc(match[1])}${phrase}${esc(match[3])}`;
}

function renderFileThreats(fileThreats = []) {
    const active = Array.isArray(fileThreats) ? fileThreats : [];
    if (active.length === 0) {
        return '<p class="empty">No profile or workspace file threats found.</p>';
    }
    return active.map(f => {
        const matches = Array.isArray(f.matches) ? f.matches : [];
        const badges = matches.map(m => `${esc(m.technique || '')} · ${esc(m.rule || '')}`).join(', ');
        const detail = matches[0] && matches[0].detail ? matches[0].detail : 'Suspicious payload in .vscode or workspace.';
        // Same key the hero eye uses (`displayPath`, or the file name).
        const key = f.displayPath || f.fileName || '';
        return `
      <div class="item" data-row data-threat-key="${esc(key)}">
        <div class="item__head">${sevPill(f.severity)}<span class="item__meta">${esc(f.scope === 'profile' ? 'User profile' : 'Workspace')}</span></div>
        <div class="item__id">${esc(key)}</div>
        ${badges ? `<div class="item__meta">${badges}</div>` : ''}
        <div class="item__title">${esc(detail)}</div>
        <div class="chips">${hashChip('sha', f.sha256, `SHA-256 of ${esc(f.displayPath || f.fileName)}`)}</div>
        <div class="item__actions">
          <button type="button" class="link" data-quarantine-file="${esc(f.filePath)}" title="Move this payload out of .vscode into quarantine">Quarantine</button>
          <button type="button" class="link" data-inspect-file="${esc(f.filePath)}" title="Open file in text editor without running it">Inspect</button>
          ${f.sha256 ? `<button type="button" class="link" data-allow-file="${esc(f.sha256)}" title="Allow this exact file SHA-256 hash">Allow</button>` : ''}
        </div>
      </div>`;
    }).join('');
}

const AUDIT_LABELS = {
    allowed: ['Allowed', 'warn'], unallowed: ['Allow revoked', ''], removed: ['Removed', 'bad'],
    installed: ['Installed', 'ok'], uninstalled: ['Uninstalled', ''], updated: ['Updated', ''],
    mode: ['Mode changed', ''], marketplace: ['Marketplace changed', ''],
    proxy: ['Proxy changed', ''], blocked: ['Blocked download', 'bad'],
    scanned: ['Scanned', 'ok'], hardening: ['Hardened', 'ok'],
    file_threat: ['File threat', 'bad'],
    quarantined: ['Quarantined', 'ok'],
    restored: ['Restored', 'warn'],
    terminated: ['Task killed', 'bad'],
    file_allowed: ['File allowed', 'warn'],
    file_unallowed: ['File allow revoked', '']
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
            if (row.fileThreatWarning) {
                // The whole row opens the File threats section. The info icon is
                // excluded by the pane script so its tooltip still works.
                return `<div class="hc__row hc__row--warn" data-open-section="threats" title="Show File threats">
              <span class="hc__icon" aria-hidden="true">${icon}</span>
              <div class="hc__body">
                <div class="hc__title-row"><span class="hc__title">${esc(row.label)}</span>${info}</div>
                <span class="hc__sub hc__sub--warn">${esc(row.sub || row.detail)}</span>${err}
              </div>
              <span class="hc__badge hc__badge--warn" title="${esc(row.detail)}" aria-label="${esc(row.sub || row.label)}">${ICON_BANG}</span>
            </div>`;
            }
            return `<div class="hc__row hc__row--warn" data-harden-arm="${esc(row.id)}">
              <span class="hc__icon" aria-hidden="true">${icon}</span>
              <div class="hc__body">
                <div class="hc__title-row"><span class="hc__title">${esc(row.label)}</span>${info}</div>
                <span class="hc__sub hc__sub--warn hc__sub--idle">${unaddressedControl(row.sub || row.detail)} · Fix (${esc(row.recommendedLabel)})</span>
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

function matchAllowedFileHash(evt, allowedFileList) {
    if (evt && typeof evt.sha256 === 'string') {
        const clean = evt.sha256.toLowerCase();
        if (allowedFileList.includes(clean)) return clean;
    }
    const raw = `${(evt && evt.detail) || ''} ${(evt && evt.id) || ''}`;
    const m = /([a-f0-9]{8,64})/i.exec(raw);
    if (!m) return null;
    const prefix = m[1].toLowerCase();
    return allowedFileList.find(h => h === prefix || h.startsWith(prefix)) || null;
}

function matchQuarantinedKey(evt, quarantinedList) {
    const idLower = String((evt && evt.id) || (evt && evt.detail) || '').toLowerCase();
    const hit = quarantinedList.find(q =>
        q && (
            (evt.quarantinedPath && q.quarantinedPath === evt.quarantinedPath)
            || (evt.filePath && q.filePath === evt.filePath)
            || (evt.sha256 && q.sha256 && q.sha256.toLowerCase() === String(evt.sha256).toLowerCase())
            || (idLower && String(q.displayPath || q.fileName || '').toLowerCase() === idLower)
        )
    );
    return hit ? (hit.quarantinedPath || hit.filePath || hit.displayPath) : null;
}

function renderAudit(events, allowlist, allowedFiles = [], quarantined = []) {
    if (events.length === 0) return '<p class="empty">No events yet. Installs, removals, and allowlist changes will appear here.</p>';
    const allowed = new Set((allowlist || []).map(a => a.toLowerCase()));
    const allowedFileList = (Array.isArray(allowedFiles) ? allowedFiles : [...allowedFiles]).map(h => String(h).toLowerCase());
    const quarantinedList = Array.isArray(quarantined) ? quarantined : [];
    const seenAllowed = new Set();
    const seenAllowedFiles = new Set();
    const seenQuarantined = new Set();
    return timeline(events, e => {
        const [label, baseTone] = AUDIT_LABELS[e.type] || [esc(e.type), ''];
        const tone = e.type === 'scanned' && e.flagged ? 'bad' : baseTone;
        const subject = e.id ? `${esc(e.id)}${e.version ? `@${esc(e.version)}` : ''}` : (e.detail ? esc(e.detail) : '');
        // Threat type stays on the subject line. Restore / Revoke get the line under it.
        const detail = e.id && e.detail ? ` · ${esc(e.detail)}` : '';
        let action = '';
        if (e.type === 'allowed' && allowed.has(e.id) && !seenAllowed.has(e.id)) {
            seenAllowed.add(e.id);
            action = `<button type="button" class="link link--sm" data-unallow="${esc(e.id)}">Revoke</button>`;
        } else if (e.type === 'file_allowed') {
            const matchedHash = matchAllowedFileHash(e, allowedFileList);
            if (matchedHash && !seenAllowedFiles.has(matchedHash)) {
                seenAllowedFiles.add(matchedHash);
                action = `<button type="button" class="link link--sm" data-unallow-file="${esc(matchedHash)}" data-unallow-label="${esc(e.id || '')}">Revoke</button>`;
            }
        } else if (e.type === 'quarantined') {
            const qKey = matchQuarantinedKey(e, quarantinedList);
            const restoreBtn = qKey && !seenQuarantined.has(qKey)
                ? (seenQuarantined.add(qKey), `<button type="button" class="link link--sm" data-restore-file="${esc(qKey)}">Restore</button>`)
                : '';
            action = `${restoreBtn}${guideLink('link link--sm')}`;
        } else if (e.type === 'removed') {
            action = guideLink('link link--sm');
        }
        return `<li class="evt evt--${tone || 'plain'}" data-row>
          <div class="run__head"><span class="run__time">${fmtClock(e.at)}</span><span class="evt__type ${tone}">${label}</span></div>
          <div class="evt__line mono">${subject}${detail}</div>
          ${action ? `<div class="evt__actions">${action}</div>` : ''}
        </li>`;
    }, 'log--audit');
}

/** Extension ids the user has allowed. Revoke uses `data-unallow`. */
function renderAllowedExtensions(allowlist = []) {
    const ids = (Array.isArray(allowlist) ? allowlist : []).map(id => String(id || '')).filter(Boolean);
    if (ids.length === 0) return '<p class="empty">No extensions allowlisted.</p>';
    return ids.map(id => `
      <div class="item" data-row>
        <div class="item__id">${esc(id)}</div>
        <div class="item__actions">
          <button type="button" class="link" data-unallow="${esc(id)}" title="Flag this extension again">Revoke</button>
        </div>
      </div>`).join('');
}

/**
 * Allowed files. Each row is the stored label: `name (hash)`.
 * A bare hash from an older setting is shown as the hash alone.
 */
function renderAllowedFiles(records = []) {
    const rows = (Array.isArray(records) ? records : [...records]).filter(record => record && record.hash);
    if (rows.length === 0) return '<p class="empty">No files allowlisted.</p>';
    return rows.map(record => {
        const hash = String(record.hash).toLowerCase();
        const label = record.label || (record.name ? `${record.name} (${hash})` : hash);
        return `
      <div class="item" data-row>
        <div class="item__id">${esc(label)}</div>
        <div class="item__actions">
          <button type="button" class="link" data-unallow-file="${esc(hash)}" data-unallow-label="${esc(label)}" title="Flag this file again">Revoke</button>
        </div>
      </div>`;
    }).join('');
}

module.exports = {
    section, timeline, renderRuns, renderExtensionThreats, renderFileThreats, renderHealthCheck,
    HARDEN_GUIDE_URL, renderAudit, renderAllowedExtensions, renderAllowedFiles, AUDIT_LABELS
};
