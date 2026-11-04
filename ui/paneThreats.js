/**
 * HTML for "what was found" lists in the side pane (`ui/paneThreats.js`).
 *
 * Two places use these lists:
 *   - The hero banner at the top: names the active threats next to the warning.
 *   - Each Scan log run: shows what that scan found.
 *
 * Pure functions (data in, HTML out). Every string goes through `esc()`.
 */

const { esc } = require('./paneFormat');

// The hero is small, so it only names a few threats and says how many more.
const HERO_MAX = 3;

// Eye control. Clicking it opens the section where this threat can be handled
// and flashes that row. Kept as one SVG so the hero and the scan log match.
const EYE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';

/**
 * Eye button for a live threat. `key` is the same string stamped on the
 * action card (`data-threat-key`), so the pane can flash that exact row.
 */
function eyeButton(section, key) {
    const label = section === 'threats' ? 'File threats' : 'Extension threats';
    return `<button type="button" class="eye" data-open-section="${section}" data-threat-key="${esc(key)}" title="Show where to act" aria-label="Show ${esc(key)} in ${label}">${EYE_ICON}</button>`;
}

/**
 * One row. The hero shows the red severity pill and the name, plus the eye.
 * It does not show the threat type, which wrapped one letter per line in a
 * narrow sidebar. The scan log also shows the reason.
 * A live threat's eye jumps to its action card.
 */
function threatRow(t, extra = '', clickable = false, nameOnly = false) {
    const section = t.kind === 'file' ? 'threats' : (t.kind === 'extension' ? 'ext-threats' : '');
    const eye = clickable && section && t.name ? eyeButton(section, t.name) : '';
    const level = esc(String(t.severity || 'high').toLowerCase());
    if (nameOnly) {
        return `<li class="found__row found__row--name">
      <span class="sev sev--${level}">${level}</span>
      <span class="found__name bad">${esc(t.name)}</span>
      ${eye}
    </li>`;
    }
    return `<li class="found__row">
      <span class="sev sev--${level}">${level}</span>
      <span class="found__name">${esc(t.name)}</span>
      <span class="found__why">${esc(t.why)}${extra}</span>
      ${eye}
    </li>`;
}

/** Hero list: first few active threats, plus "+N more" when there are extra. */
function renderHeroThreats(threats = []) {
    if (!Array.isArray(threats) || threats.length === 0) return '';
    const rows = threats.slice(0, HERO_MAX).map(t => threatRow(t, '', true, true)).join('');
    const hidden = threats.length - HERO_MAX;
    const more = hidden > 0 ? `<li class="found__more">+${hidden} more in the logs below</li>` : '';
    return `<ul class="found found--hero">${rows}${more}</ul>`;
}

/** Scan log list: everything that run found. Removed extensions say so. */
function renderRunFound(details = []) {
    if (!Array.isArray(details) || details.length === 0) return '';
    // A removed finding has nowhere left to act, so it does not get an eye.
    const rows = details.map(t => threatRow(t, t.removed ? ' · <span class="ok">removed</span>' : '', !t.removed)).join('');
    return `<ul class="found">${rows}</ul>`;
}

module.exports = { renderHeroThreats, renderRunFound };
