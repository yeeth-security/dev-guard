/**
 * Audit log: who changed what, and when.
 *
 * Records security-relevant events so the user can see a timeline in the
 * side pane:
 *   - allowed / unallowed      an extension was added to or removed from the allowlist
 *   - removed                  DevGuard uninstalled a flagged extension
 *   - blocked                  DevGuard blocked a malicious/unscanned marketplace download
 *   - installed / uninstalled / updated   extension inventory changed
 *   - mode / marketplace / proxy / hardening   a setting changed from the pane
 *
 * Multi-window synchronization:
 *   VS Code / Cursor caches `context.globalState` in memory per Extension Host,
 *   so an event recorded in Window 1 (which owns the local proxy port) would
 *   not automatically appear in Window 2's `globalState`. When `globalStorageUri`
 *   is available, we also mirror and merge `audit-log.json` on disk so every
 *   open window always reads and displays the complete, up-to-date audit log.
 */

const fs = require('fs');
const path = require('path');
const { DEFAULT_HISTORY_LIMIT, clampHistoryLimit } = require('./history');

const AUDIT_KEY = 'devGuard.auditLog';
const SNAPSHOT_KEY = 'devGuard.installedSnapshot';
const AUDIT_FILE = 'audit-log.json';
const MAX_AUDIT = DEFAULT_HISTORY_LIMIT;
const REMOVAL_DEDUPE_MS = 60 * 1000;
const BLOCK_DEDUPE_MS = 5 * 1000;

function getAuditFilePath(context) {
    const dir = context && context.globalStorageUri && context.globalStorageUri.fsPath;
    return typeof dir === 'string' && dir ? path.join(dir, AUDIT_FILE) : null;
}

function readDiskAudit(context) {
    const filePath = getAuditFilePath(context);
    if (!filePath) return [];
    try {
        if (!fs.existsSync(filePath)) return [];
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return Array.isArray(parsed) ? parsed : [];
    } catch (_error) {
        return [];
    }
}

function writeDiskAudit(context, list) {
    const filePath = getAuditFilePath(context);
    if (!filePath) return;
    try {
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, JSON.stringify(list), 'utf8');
    } catch (_error) { /* ignore disk write errors */ }
}

function readStateList(context, key) {
    try {
        const raw = context.globalState.get(key);
        return Array.isArray(raw) ? raw : [];
    } catch (_error) {
        return [];
    }
}

function writeState(context, key, value) {
    try {
        void context.globalState.update(key, value);
    } catch (error) {
        console.warn(`Could not save ${key}:`, error);
    }
}

/** Merges in-memory `globalState` entries with shared `audit-log.json` entries without duplicates. */
function readMergedAuditList(context) {
    const fromState = readStateList(context, AUDIT_KEY);
    const fromDisk = readDiskAudit(context);
    if (fromDisk.length === 0) return fromState;
    if (fromState.length === 0) return fromDisk;

    const combined = [...fromState, ...fromDisk];
    combined.sort((a, b) => (b.at || 0) - (a.at || 0));
    const deduped = [];
    for (const item of combined) {
        if (!item || typeof item !== 'object') continue;
        const isDup = deduped.some(existing =>
            existing.type === item.type
            && (existing.id || '') === (item.id || '')
            && (existing.detail || '') === (item.detail || '')
            && Math.abs((existing.at || 0) - (item.at || 0)) < 2000
        );
        if (!isDup) deduped.push(item);
    }
    return deduped;
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

/** Compares two snapshots and returns audit entries for the differences. */
function diffSnapshots(previous, current, now, lastEventFor = () => null) {
    const events = [];
    for (const [id, version] of Object.entries(current)) {
        if (!(id in previous)) events.push({ at: now, type: 'installed', id, version });
        else if (previous[id] !== version) events.push({ at: now, type: 'updated', id, version, detail: `from ${previous[id]}` });
    }
    for (const [id, version] of Object.entries(previous)) {
        if (id in current) continue;
        const last = lastEventFor(id);
        if (last && last.type === 'removed') continue;
        events.push({ at: now, type: 'uninstalled', id, version });
    }
    return events;
}

function createAuditLog(context, options = {}) {
    const listeners = new Set();
    const emit = () => listeners.forEach(fn => { try { fn(); } catch (_e) { /* ignore */ } });
    const limit = () => clampHistoryLimit(options.getLimit ? options.getLimit() : undefined);

    const list = () => readMergedAuditList(context).slice(0, limit());
    const lastEventFor = id => list().find(e => e.id === String(id).toLowerCase()) || null;

    function recordMany(entries, existing = list()) {
        if (entries.length === 0) return;
        const normalized = entries.map(e => ({ ...e, id: e.id ? String(e.id).toLowerCase() : undefined }));
        const merged = [...normalized.reverse(), ...existing];
        merged.sort((a, b) => (b.at || 0) - (a.at || 0));
        const capped = merged.slice(0, limit());
        writeState(context, AUDIT_KEY, capped);
        writeDiskAudit(context, capped);
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
                const id = String(e.id).toLowerCase();
                existing = existing.filter(x => !(x.type === 'uninstalled' && x.id === id && e.at - (x.at || 0) < REMOVAL_DEDUPE_MS));
            } else if (e.type === 'blocked' && e.id) {
                const id = String(e.id).toLowerCase();
                existing = existing.filter(x => !(x.type === 'blocked' && x.id === id && Math.abs(e.at - (x.at || 0)) < BLOCK_DEDUPE_MS));
            }
            recordMany([e], existing);
        },
        syncInstalled(extensions, now = Date.now()) {
            const current = snapshotOf(extensions);
            let previous = null;
            try { previous = context.globalState.get(SNAPSHOT_KEY) || null; } catch (_e) { previous = null; }
            writeState(context, SNAPSHOT_KEY, current);
            if (!previous || typeof previous !== 'object') return [];
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

async function scanAfterInstall(monitor, audit, added) {
    const result = await monitor.executeCycle('install');
    const flagged = new Set(Array.isArray(result && result.flaggedIds) ? result.flaggedIds : []);
    const at = result && Number.isFinite(result.startedAt) ? result.startedAt : Date.now();
    for (const ext of added) {
        const id = String(ext.id || '').toLowerCase();
        const hit = flagged.has(id);
        audit.record({ at, type: 'scanned', id, version: ext.version, flagged: hit, detail: hit ? 'after install · flagged' : 'after install · clear' });
    }
}

module.exports = { AUDIT_KEY, SNAPSHOT_KEY, MAX_AUDIT, snapshotOf, diffSnapshots, createAuditLog, scanAfterInstall };
