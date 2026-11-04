/**
 * Quarantine, safe file inspection, and SHA-256 file allowlist (`scanner/quarantine.js`).
 *
 * Why this file exists:
 *   When Dev-Guard detects a malicious script or config in `~/.vscode/` or a
 *   workspace's `.vscode/`, the user needs a safe way to neutralize it without
 *   running it, restore it from quarantine if needed, inspect its source code,
 *   or allowlist/revoke a file by its SHA-256 content hash.
 */

const fs = require('fs');
const path = require('path');

const ALLOWED_FILES_SETTING = 'allowedFiles';
const QUARANTINE_STATE_KEY = 'devGuard.quarantinedFiles';
const MAX_QUARANTINED = 100;
const FILE_HASH_RE = /^[a-f0-9]{16,64}$/i;
// Stored form is "name (hash)". A bare hash is still accepted from older settings.
const NAMED_FILE_RE = /^(.*\S)\s+\(([a-f0-9]{16,64})\)$/i;

/**
 * Turns a file name and its content hash into the allowlist entry.
 * Example: `.vscode/tasks.json (abc123...)`. A missing name keeps the bare hash.
 */
function formatAllowedFileEntry(name, hash) {
    const clean = String(hash || '').trim().toLowerCase();
    if (!FILE_HASH_RE.test(clean)) return '';
    const label = String(name || '').replace(/\s+/g, ' ').trim();
    return label ? `${label} (${clean})` : clean;
}

/** Reads one allowlist string back into `{ name, hash, label }`. */
function parseAllowedFileEntry(raw) {
    const text = String(raw || '').trim();
    if (!text) return null;
    const named = NAMED_FILE_RE.exec(text);
    if (named) {
        const hash = named[2].toLowerCase();
        const name = named[1].trim();
        return { name, hash, label: `${name} (${hash})` };
    }
    if (!FILE_HASH_RE.test(text)) return null;
    const hash = text.toLowerCase();
    return { name: '', hash, label: hash };
}

/** Normalizes allowlist entries into a lowercase Set of SHA-256 hashes. */
function normalizeAllowedFiles(raw) {
    const set = new Set();
    for (const item of Array.isArray(raw) ? raw : []) {
        const parsed = parseAllowedFileEntry(item);
        if (parsed) set.add(parsed.hash);
    }
    return set;
}

function readRawAllowedFiles(vscodeApi) {
    try {
        const raw = vscodeApi.workspace.getConfiguration('devGuard').get(ALLOWED_FILES_SETTING, []);
        return Array.isArray(raw) ? raw : [];
    } catch (_e) {
        return [];
    }
}

/** Reads `devGuard.allowedFiles` as a Set of SHA-256 hashes. Names are ignored. */
function readAllowedFiles(vscodeApi) {
    return normalizeAllowedFiles(readRawAllowedFiles(vscodeApi));
}

/**
 * Reads allowlist entries for the pane. One record per hash.
 * A named entry wins over an older bare hash for the same content.
 */
function readAllowedFileRecords(vscodeApi) {
    const byHash = new Map();
    for (const item of readRawAllowedFiles(vscodeApi)) {
        const parsed = parseAllowedFileEntry(item);
        if (!parsed) continue;
        const prev = byHash.get(parsed.hash);
        if (!prev || (parsed.name && !prev.name)) byHash.set(parsed.hash, parsed);
    }
    return [...byHash.values()].sort((a, b) => a.label.localeCompare(b.label));
}

async function writeAllowedFileRecords(vscodeApi, records) {
    const lines = (Array.isArray(records) ? records : [])
        .map(record => formatAllowedFileEntry(record && record.name, record && record.hash))
        .filter(Boolean)
        .sort();
    const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
    await vscodeApi.workspace.getConfiguration('devGuard').update(ALLOWED_FILES_SETTING, lines, target);
}

/**
 * Adds a file to `devGuard.allowedFiles` at Global scope.
 * The saved string is `name (hash)` when a name is known.
 */
async function allowFileHash(vscodeApi, sha256, name) {
    const clean = String(sha256 || '').trim().toLowerCase();
    if (!FILE_HASH_RE.test(clean)) return;
    const current = readAllowedFileRecords(vscodeApi);
    const existing = current.find(record => record.hash === clean);
    const records = current.filter(record => record.hash !== clean);
    const nextName = String(name || '').trim() || (existing && existing.name) || '';
    records.push({ name: nextName, hash: clean });
    await writeAllowedFileRecords(vscodeApi, records);
}

/** Removes a file hash (or matching hex prefix) from `devGuard.allowedFiles`. */
async function unallowFileHash(vscodeApi, sha256) {
    const clean = String(sha256 || '').trim().toLowerCase();
    if (!clean) return;
    const kept = readAllowedFileRecords(vscodeApi).filter(record => {
        return !(record.hash === clean || (clean.length >= 8 && record.hash.startsWith(clean)));
    });
    await writeAllowedFileRecords(vscodeApi, kept);
}

/** Filters out findings whose SHA-256 hash is allowlisted or whose file was already removed. */
function filterActiveFileFindings(findings, allowedHashes = new Set(), io = {}) {
    const existsSync = io.existsSync || fs.existsSync;
    return (Array.isArray(findings) ? findings : []).filter(f => {
        if (!f || !f.filePath) return false;
        if (f.sha256 && allowedHashes instanceof Set && allowedHashes.has(String(f.sha256).toLowerCase())) {
            return false;
        }
        try { return Boolean(existsSync(f.filePath)); } catch (_e) { return true; }
    });
}

/** Resolves the base quarantine folder inside globalStorageUri (or extensionPath fallback). */
function getQuarantineRoot(context) {
    if (context && context.globalStorageUri && context.globalStorageUri.fsPath) {
        return path.join(context.globalStorageUri.fsPath, 'quarantine');
    }
    return path.join((context && context.extensionPath) || __dirname, '.quarantine');
}

/** Lists previously quarantined file records stored in `context.globalState`. */
function listQuarantined(context) {
    try {
        const raw = context && context.globalState ? context.globalState.get(QUARANTINE_STATE_KEY) : null;
        return Array.isArray(raw) ? raw : [];
    } catch (_e) { return []; }
}

/** Moves a flagged file into the quarantine directory and records metadata in `globalState`. */
function quarantineFinding(context, finding, io = {}) {
    const mkdirSync = io.mkdirSync || fs.mkdirSync;
    const renameSync = io.renameSync || fs.renameSync;
    const copyFileSync = io.copyFileSync || fs.copyFileSync;
    const unlinkSync = io.unlinkSync || fs.unlinkSync;
    const rmSync = io.rmSync || fs.rmSync;
    const writeFileSync = io.writeFileSync || fs.writeFileSync;
    const now = io.now ? io.now() : Date.now();
    if (!finding || !finding.filePath) return { ok: false, error: 'Missing file path.' };

    try {
        const shortHash = String(finding.sha256 || 'unknown').slice(0, 12);
        const destDir = path.join(getQuarantineRoot(context), `${now}-${shortHash}`);
        mkdirSync(destDir, { recursive: true });
        const destFile = path.join(destDir, path.basename(finding.filePath));

        try {
            renameSync(finding.filePath, destFile);
        } catch (_renameErr) {
            if (finding.isDirectory && typeof rmSync === 'function') rmSync(finding.filePath, { recursive: true, force: true });
            else { copyFileSync(finding.filePath, destFile); unlinkSync(finding.filePath); }
        }

        const record = {
            at: now, filePath: finding.filePath,
            displayPath: finding.displayPath || path.basename(finding.filePath),
            fileName: finding.fileName || path.basename(finding.filePath),
            scope: finding.scope || 'workspace', sha256: finding.sha256 || null,
            severity: finding.severity || 'high',
            rules: (finding.matches || []).map(m => m.rule),
            techniques: (finding.matches || []).map(m => m.technique),
            quarantinedPath: destFile
        };
        try { writeFileSync(path.join(destDir, 'metadata.json'), JSON.stringify(record, null, 2), 'utf8'); } catch (_e) { /* ignore */ }
        if (context && context.globalState) {
            void context.globalState.update(QUARANTINE_STATE_KEY, [record, ...listQuarantined(context)].slice(0, MAX_QUARANTINED));
        }
        return { ok: true, quarantinedPath: destFile, record };
    } catch (error) {
        return { ok: false, error: String((error && error.message) || error) };
    }
}

/** Restores a quarantined file back to its original path and removes it from the quarantine list. */
function restoreQuarantinedFile(context, key, io = {}) {
    const mkdirSync = io.mkdirSync || fs.mkdirSync;
    const renameSync = io.renameSync || fs.renameSync;
    const copyFileSync = io.copyFileSync || fs.copyFileSync;
    const unlinkSync = io.unlinkSync || fs.unlinkSync;
    const rmSync = io.rmSync || fs.rmSync;
    const target = String(key || '').trim();
    if (!target) return { ok: false, error: 'Missing quarantine identifier.' };

    const all = listQuarantined(context);
    const lower = target.toLowerCase();
    const idx = all.findIndex(q =>
        q && (
            q.quarantinedPath === target
            || q.filePath === target
            || (q.sha256 && q.sha256.toLowerCase() === lower)
            || String(q.displayPath || q.fileName || '').toLowerCase() === lower
        )
    );
    if (idx < 0) return { ok: false, error: 'Quarantined file record not found.' };
    const record = all[idx];

    try {
        mkdirSync(path.dirname(record.filePath), { recursive: true });
        try {
            renameSync(record.quarantinedPath, record.filePath);
        } catch (_renameErr) {
            copyFileSync(record.quarantinedPath, record.filePath);
            unlinkSync(record.quarantinedPath);
        }
        try { rmSync?.(path.dirname(record.quarantinedPath), { recursive: true, force: true }); } catch (_e) { /* ignore */ }
        if (context && context.globalState) {
            const next = all.filter((_, i) => i !== idx);
            void context.globalState.update(QUARANTINE_STATE_KEY, next);
        }
        return { ok: true, restoredPath: record.filePath, record };
    } catch (error) {
        return { ok: false, error: String((error && error.message) || error) };
    }
}

/** Opens a flagged file in the VS Code text editor so the user can inspect it safely. */
async function inspectFinding(vscodeApi, finding) {
    if (!vscodeApi || !vscodeApi.workspace || !vscodeApi.window || !finding || !finding.filePath) return false;
    try {
        const uri = vscodeApi.Uri && typeof vscodeApi.Uri.file === 'function' ? vscodeApi.Uri.file(finding.filePath) : finding.filePath;
        const doc = await vscodeApi.workspace.openTextDocument(uri);
        await vscodeApi.window.showTextDocument(doc, { preview: true });
        return true;
    } catch (_e) { return false; }
}

module.exports = {
    ALLOWED_FILES_SETTING, QUARANTINE_STATE_KEY, MAX_QUARANTINED,
    formatAllowedFileEntry, parseAllowedFileEntry, normalizeAllowedFiles,
    readAllowedFiles, readAllowedFileRecords, allowFileHash, unallowFileHash,
    filterActiveFileFindings, getQuarantineRoot, listQuarantined,
    quarantineFinding, restoreQuarantinedFile, inspectFinding
};
