/**
 * Plain-English list of what a scan found (`threats.js`).
 *
 * Why this file exists:
 *   The pane used to say only "1 threat found". Users could not tell WHAT was
 *   found without digging. This module turns raw scan findings (flagged
 *   extensions and suspicious files) into one small, uniform list:
 *     { kind, name, severity, why, removed }
 *   The same list is saved on each Scan log run and shown in the hero banner.
 *
 * No `vscode` import, so it is easy to unit test.
 */

const { humanize } = require('./ui/paneFormat');

// Keep saved runs small. The Scan log keeps up to 200 runs in globalState.
const MAX_DETAILS = 25;

/**
 * Builds the threat list for one scan.
 * @param {{found?: Array<{extension: any, advisory: any}>, fileThreats?: any[], removedIds?: Set<string>}} input
 *   `found` are flagged extensions. `removedIds` are lowercase ids already uninstalled.
 */
function describeThreats({ found = [], fileThreats = [], removedIds = new Set() } = {}) {
    const out = [];

    // Flagged extensions: name is id@version, reason is the advisory title.
    for (const { extension, advisory } of Array.isArray(found) ? found : []) {
        const id = String((extension && extension.id) || 'unknown');
        const version = (extension && extension.packageJSON && extension.packageJSON.version) || 'unknown';
        out.push({
            kind: 'extension',
            name: `${id}@${version}`,
            severity: String((advisory && advisory.severity) || 'high').toLowerCase(),
            why: humanize(advisory && advisory.title) || 'Malicious extension advisory',
            removed: removedIds.has(id.toLowerCase())
        });
    }

    // Suspicious files: name is the path, reason is the first rule that matched.
    for (const f of Array.isArray(fileThreats) ? fileThreats : []) {
        const first = (f && Array.isArray(f.matches) && f.matches[0]) || {};
        out.push({
            kind: 'file',
            name: String((f && (f.displayPath || f.fileName)) || 'unknown file'),
            severity: String((f && f.severity) || 'high').toLowerCase(),
            why: humanize(first.rule) || 'Suspicious file',
            removed: false
        });
    }

    return out.slice(0, MAX_DETAILS);
}

/**
 * Threats that still need attention right now, for the hero banner.
 * Extensions come from the live list when the pane has one, so an uninstall
 * or allow drops the row immediately. Otherwise they come from the latest
 * run (minus the ones already removed).
 * Files come from the live file-threat list, so quarantined files drop off.
 */
function activeThreats(runs = [], fileThreats = [], extensionThreats) {
    const extensions = Array.isArray(extensionThreats)
        ? extensionThreats.map(t => ({
            kind: 'extension',
            name: `${t.id}@${t.version || 'unknown'}`,
            severity: String(t.severity || 'high').toLowerCase(),
            why: humanize(t.title) || 'Malicious extension advisory',
            removed: false
        }))
        : extensionRowsFromRuns(runs);
    return [...extensions, ...describeThreats({ fileThreats })];
}

/** Flagged extensions saved on the newest scan run that are not marked removed. */
function extensionRowsFromRuns(runs) {
    const last = Array.isArray(runs) ? runs[0] : null;
    const details = last && Array.isArray(last.details) ? last.details : [];
    return details.filter(d => d.kind === 'extension' && !d.removed);
}

module.exports = { MAX_DETAILS, describeThreats, activeThreats };
