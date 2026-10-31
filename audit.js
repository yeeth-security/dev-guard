/**
 * Audit log: who changed what, and when.
 *
 * Records security-relevant events so the user can see a timeline in the
 * side pane:
 *   - allowed / unallowed      an extension was added to or removed from the allowlist
 *   - removed                  DevGuard uninstalled a flagged extension
 *   - installed / uninstalled / updated   extension inventory changed
 *   - mode / marketplace       a DevGuard setting changed from the pane
 *
 * Install tracking works by diffing a persisted snapshot of installed
 * extensions (id -> version). The first run only saves the snapshot, so a
 * fresh install does not log every existing extension as "installed".
 *
 * No `vscode` import, so it is easy to unit test.
 */

const { DEFAULT_HISTORY_LIMIT, clampHistoryLimit } = require('./history');

const AUDIT_KEY = 'devGuard.auditLog';
const SNAPSHOT_KEY = 'devGuard.installedSnapshot';
// Default cap. The live cap comes from the `devGuard.historyLimit` setting.
const MAX_AUDIT = DEFAULT_HISTORY_LIMIT;
// An "uninstalled" entry this close before a "removed" entry for the same id is
// the same event seen twice (see `record`). A removal cycle takes well under this.
const REMOVAL_DEDUPE_MS = 60 * 1000;

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

/** Builds `{ "publisher.name": "1.2.3" }` from `vscode.extensions.all`, skipping builtins. */
function snapshotOf(extensions) {
    const snap = {};
    for (const ext of Array.isArray(extensions) ? extensions : []) {
        if (!ext || !ext.id || (ext.packageJSON && ext.packageJSON.isBuiltin)) continue;
        snap[ext.id.toLowerCase()] = (ext.packageJSON && ext.packageJSON.version) || 'unknown';
    }
    return snap;
}

/**
 * Compares two snapshots and returns audit entries for the differences.
 * `lastEventFor(id)` lets us skip an "uninstalled" entry right after DevGuard
 * itself removed the extension, so one removal is not logged twice.
 */
function diffSnapshots(previous, current, now, lastEventFor = () => null) {
    const events = [];
    for (const [id, version] of Object.entries(current)) {
        if (!(id in previous)) events.push({ at: now, type: 'installed', id, version });
        else if (previous[id] !== version) events.push({ at: now, type: 'updated', id, version, detail: `from ${previous[id]}` });
    }
    for (const [id, version] of Object.entries(previous)) {
        if (id in current) continue;
        const last = lastEventFor(id);
        if (last && last.type === 'removed') continue; // already logged as a DevGuard removal
        events.push({ at: now, type: 'uninstalled', id, version });
    }
    return events;
}

/**
 * Creates the audit log bound to one extension context.
 * @param {any} context
 * @param {{getLimit?: () => any}} [options] `getLimit` reads the user's
 *   `devGuard.historyLimit` setting (see history.js for the clamping rules).
 */
function createAuditLog(context, options = {}) {
    const listeners = new Set();
    const emit = () => listeners.forEach(fn => { try { fn(); } catch (_e) { /* ignore */ } });
    const limit = () => clampHistoryLimit(options.getLimit ? options.getLimit() : undefined);

    // Sliced on read too, so lowering the limit trims the pane immediately.
    const list = () => readList(context, AUDIT_KEY).slice(0, limit());
    const lastEventFor = id => list().find(e => e.id === String(id).toLowerCase()) || null;

    function recordMany(entries, existing = list()) {
        if (entries.length === 0) return;
        // IDs are stored lower-case so lookups are consistent.
        const normalized = entries.map(e => ({ ...e, id: e.id ? String(e.id).toLowerCase() : undefined }));
        // Newest first, ordered by timestamp (not insertion). Entries may be
        // recorded out of order: e.g. the post-install "scanned" entry is
        // stamped with the scan's start time but written after the scan ends.
        // Stable sort keeps same-timestamp entries in insertion order.
        const merged = [...normalized.reverse(), ...existing];
        merged.sort((a, b) => (b.at || 0) - (a.at || 0));
        write(context, AUDIT_KEY, merged.slice(0, limit()));
        emit();
    }

    return {
        list,
        lastEventFor,
        /** @param {{type: string, id?: string, version?: string, detail?: string, at?: number}} entry */
        record(entry) {
            const e = { at: Date.now(), ...entry };
            let existing = list();
            if (e.type === 'removed' && e.id) {
                // The uninstall command fires `extensions.onDidChange` before it
                // resolves, so syncInstalled may already have logged "uninstalled"
                // for this very removal. Drop that duplicate; "removed" wins.
                const id = String(e.id).toLowerCase();
                existing = existing.filter(x => !(x.type === 'uninstalled' && x.id === id && e.at - (x.at || 0) < REMOVAL_DEDUPE_MS));
            }
            recordMany([e], existing);
        },
        /**
         * Diffs the installed extensions against the saved snapshot and logs
         * installs, uninstalls, and updates. Call at activation and on
         * `vscode.extensions.onDidChange`.
         */
        syncInstalled(extensions, now = Date.now()) {
            const current = snapshotOf(extensions);
            let previous = null;
            try { previous = context.globalState.get(SNAPSHOT_KEY) || null; } catch (_e) { previous = null; }
            write(context, SNAPSHOT_KEY, current);
            if (!previous || typeof previous !== 'object') return []; // first run: baseline only
            const events = diffSnapshots(previous, current, now, lastEventFor);
            recordMany(events);
            return events;
        },
        onChange(fn) {
            listeners.add(fn);
            return () => listeners.delete(fn);
        }
    };
}

/**
 * Runs a scan immediately after extensions were installed or updated, then
 * records one "scanned" audit entry per extension saying whether it was clear
 * or flagged. `monitor` and `audit` are passed in so this has no VS Code
 * dependency and is easy to test.
 * @param {{executeCycle: (trigger: string) => Promise<any>}} monitor
 * @param {{record: (entry: object) => void}} audit
 * @param {Array<{id: string, version?: string}>} added installed/updated events
 */
async function scanAfterInstall(monitor, audit, added) {
    const result = await monitor.executeCycle('install');
    const flagged = new Set(Array.isArray(result && result.flaggedIds) ? result.flaggedIds : []);
    // Stamp with the scan's start time so the entry sorts between "installed"
    // and any "removed" the same scan produced (installed → scanned → removed).
    const at = result && Number.isFinite(result.startedAt) ? result.startedAt : Date.now();
    for (const ext of added) {
        const id = String(ext.id || '').toLowerCase();
        const hit = flagged.has(id);
        audit.record({ at, type: 'scanned', id, version: ext.version, flagged: hit, detail: hit ? 'after install · flagged' : 'after install · clear' });
    }
}

module.exports = { AUDIT_KEY, SNAPSHOT_KEY, MAX_AUDIT, snapshotOf, diffSnapshots, createAuditLog, scanAfterInstall };
