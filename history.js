/**
 * Scan history, extension hashes, and removed-extension log.
 *
 * Why this file exists:
 *   The dashboard shows what DevGuard checked and when. To make that
 *   trustworthy, each scan records:
 *     - a SHA-256 hash of every installed extension's package.json
 *     - a SHA-256 hash of the advisory set the scan compared against
 *   Hashes let a user prove later which exact files were checked.
 *
 * Storage:
 *   Everything lives in `context.globalState`. The number of scan runs kept is
 *   the `devGuard.historyLimit` setting (default 200, also used by the audit
 *   log). Removals keep the last 100. Only the newest full inventory
 *   (per-extension hashes) is stored, to keep state small.
 *
 * No `vscode` import here, so it is easy to unit test.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RUNS_KEY = 'devGuard.scanHistory';
const REMOVED_KEY = 'devGuard.removedExtensions';
const INVENTORY_KEY = 'devGuard.lastInventory';
// Default / bounds for the `devGuard.historyLimit` setting. Shared with audit.js.
const DEFAULT_HISTORY_LIMIT = 200;
const MIN_HISTORY_LIMIT = 10;
const MAX_HISTORY_LIMIT = 2000;
const MAX_RUNS = DEFAULT_HISTORY_LIMIT; // kept for callers/tests that want the default
const MAX_REMOVED = 100;

/**
 * Turns a raw setting value into a safe list limit.
 * Non-numbers fall back to the default; numbers are clamped to the bounds.
 */
function clampHistoryLimit(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return DEFAULT_HISTORY_LIMIT;
    return Math.min(MAX_HISTORY_LIMIT, Math.max(MIN_HISTORY_LIMIT, Math.floor(n)));
}

/** @param {string} text */
function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Hashes each non-builtin extension's package.json.
 * @param {Array<any>} extensions `vscode.extensions.all`
 * @param {Map<string, {source?: string}>} [provenance] from registry.js
 * @param {Function} [readFileSync] injectable for tests
 * @returns {Array<{id: string, version: string, source: string, hash: string|null}>}
 */
function hashExtensions(extensions, provenance = new Map(), readFileSync = fs.readFileSync) {
    const rows = [];
    for (const ext of Array.isArray(extensions) ? extensions : []) {
        if (!ext || !ext.id) continue;
        if (ext.packageJSON && ext.packageJSON.isBuiltin) continue;
        let hash = null;
        try {
            hash = sha256(readFileSync(path.join(ext.extensionPath, 'package.json'), 'utf8'));
        } catch (_error) {
            // Unreadable manifest: keep the row but leave hash null.
        }
        const prov = provenance.get(String(ext.id).toLowerCase());
        rows.push({
            id: ext.id,
            version: (ext.packageJSON && ext.packageJSON.version) || 'unknown',
            source: prov && prov.source ? prov.source : 'unknown',
            hash
        });
    }
    return rows.sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * One stable hash for the whole advisory set used in a scan.
 * Sorted first so order of fetching does not change the result.
 */
function hashAdvisorySet(entries) {
    const keys = (Array.isArray(entries) ? entries : [])
        .map(e => e && (e.id || `${e.extensionId}@${e.version}`))
        .filter(Boolean)
        .sort();
    return sha256(keys.join('\n'));
}

/** One stable hash for the whole inventory. */
function hashInventory(rows) {
    return sha256(rows.map(r => `${r.id}@${r.version}:${r.hash || '-'}`).join('\n'));
}

function readList(context, key) {
    try {
        const raw = context.globalState.get(key);
        return Array.isArray(raw) ? raw : [];
    } catch (_error) {
        return [];
    }
}

function write(context, key, value) {
    try {
        void context.globalState.update(key, value);
    } catch (error) {
        console.warn(`Could not save ${key}:`, error);
    }
}

/**
 * Creates the history store bound to one extension context.
 * @param {any} context
 * @param {{getLimit?: () => any}} [options] `getLimit` reads the user's
 *   `devGuard.historyLimit` setting; it is called on every read/write so a
 *   settings change applies at once, no reload needed.
 */
function createHistoryStore(context, options = {}) {
    const listeners = new Set();
    const emit = () => listeners.forEach(fn => { try { fn(); } catch (_e) { /* ignore */ } });
    const limit = () => clampHistoryLimit(options.getLimit ? options.getLimit() : undefined);

    return {
        // Sliced on read too, so lowering the limit trims the pane immediately.
        listRuns: () => readList(context, RUNS_KEY).slice(0, limit()),
        listRemoved: () => readList(context, REMOVED_KEY),
        getLastInventory: () => {
            try { return context.globalState.get(INVENTORY_KEY) || null; } catch (_e) { return null; }
        },

        /** Adds one scan run (newest first) and stores its inventory. */
        recordRun(run, inventory) {
            const runs = [run, ...readList(context, RUNS_KEY)].slice(0, limit());
            write(context, RUNS_KEY, runs);
            if (Array.isArray(inventory)) {
                write(context, INVENTORY_KEY, { at: run.at, rows: inventory });
            }
            emit();
        },

        /** Adds removed extensions (newest first). `action` is auto or manual. */
        recordRemoved(items, action, now = Date.now()) {
            const fresh = (Array.isArray(items) ? items : []).map(item => ({
                at: now,
                action,
                id: item.extension.id,
                version: (item.extension.packageJSON && item.extension.packageJSON.version) || 'unknown',
                advisoryId: (item.advisory && item.advisory.id) || null,
                severity: (item.advisory && item.advisory.severity) || 'unknown',
                title: (item.advisory && item.advisory.title) || null,
                permalink: (item.advisory && item.advisory.permalink) || null
            }));
            if (fresh.length === 0) return;
            write(context, REMOVED_KEY, [...fresh, ...readList(context, REMOVED_KEY)].slice(0, MAX_REMOVED));
            emit();
        },

        /** Subscribe to changes. Returns an unsubscribe function. */
        onChange(fn) {
            listeners.add(fn);
            return () => listeners.delete(fn);
        }
    };
}

module.exports = {
    RUNS_KEY,
    REMOVED_KEY,
    INVENTORY_KEY,
    DEFAULT_HISTORY_LIMIT,
    MIN_HISTORY_LIMIT,
    MAX_HISTORY_LIMIT,
    clampHistoryLimit,
    MAX_RUNS,
    MAX_REMOVED,
    sha256,
    hashExtensions,
    hashAdvisorySet,
    hashInventory,
    createHistoryStore
};
