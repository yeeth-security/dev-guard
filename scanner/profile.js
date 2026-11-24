/**
 * User-profile `.vscode/` implant scanner (`scanner/profile.js`).
 *
 * Why this file exists:
 *   The `vscode-enc` malware campaign stages `vscode-bootstrap.sh`,
 *   `env-setup.js`, `package.json`, `package-lock.json`, the npm config file,
 *   `node_modules/`, and a portable Node.js binary directly inside the user's
 *   `~/.vscode/` directory alongside legitimate extensions.
 *
 *   A normal `~/.vscode/` folder only holds `extensions/`, `cli/`, and editor
 *   state files like `argv.json`. Scripts, npm manifests, or a portable Node
 *   runtime at the root of `~/.vscode/` are strong indicators of an implant.
 *
 * Design:
 *   - Pure module with injectable filesystem (`fs`) and `os.homedir` for tests.
 *   - Inspects both `~/.vscode` and the active editor's profile root derived
 *     from installed extension paths (e.g. `~/.cursor`, `~/.vscodium`).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { MAX_SCAN_BYTES, NPM_CONFIG_FILE, sha256Text, highestSeverity, scanFileContent } = require('./rules');

// File extensions that should never sit loose at the root of ~/.vscode/.
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|js|mjs|cjs|py|ps1|bat|cmd|vbs)$/i;

// Exact file or directory names that indicate a staged npm project in ~/.vscode/.
const STAGED_MANIFEST_NAMES = new Set([
    'package.json',
    'package-lock.json',
    NPM_CONFIG_FILE,
    'node_modules'
]);

// Matches a portable Node.js binary or extracted distribution folder in ~/.vscode/.
const PORTABLE_NODE_RE = /^(node|node\.exe|node-v\d+\.\d+\.\d+.*)$/i;

/**
 * Resolves the candidate user-profile `.vscode` directories to scan.
 * Includes `~/.vscode` plus the parent directory of any `extensions/` folder
 * seen in `vscode.extensions.all`.
 */
function resolveProfileDirs({ extensions = [], homedir = os.homedir } = {}) {
    const dirs = new Set();
    try {
        const home = typeof homedir === 'function' ? homedir() : '';
        if (home) dirs.add(path.join(home, '.vscode'));
    } catch (_e) {
        // Ignore homedir lookup errors.
    }

    for (const ext of Array.isArray(extensions) ? extensions : []) {
        if (!ext || !ext.extensionPath || (ext.packageJSON && ext.packageJSON.isBuiltin)) continue;
        const extDir = path.dirname(ext.extensionPath);
        if (path.basename(extDir).toLowerCase() === 'extensions') {
            dirs.add(path.dirname(extDir));
        }
    }
    return [...dirs];
}

/** Reads up to MAX_SCAN_BYTES from a file safely. Returns '' on error. */
function readSafeSlice(filePath, readFileSync = fs.readFileSync) {
    try {
        const raw = readFileSync(filePath, 'utf8');
        return String(raw || '').slice(0, MAX_SCAN_BYTES);
    } catch (_e) {
        return '';
    }
}

/**
 * Scans a single user-profile directory (such as `~/.vscode`) for staged
 * scripts, manifests, `node_modules`, and portable Node runtimes.
 */
function scanSingleProfileDir(profileDir, io = {}) {
    const readdirSync = io.readdirSync || fs.readdirSync;
    const statSync = io.statSync || fs.statSync;
    const readFileSync = io.readFileSync || fs.readFileSync;

    let entries = [];
    try {
        entries = readdirSync(profileDir);
    } catch (_e) {
        return [];
    }

    const findings = [];
    const folderLabel = path.basename(profileDir) || '.vscode';

    for (const rawName of entries) {
        const name = String(rawName || '');
        const lower = name.toLowerCase();
        if (!name || lower === 'extensions' || lower === 'cli' || lower === 'argv.json') continue;

        const isScript = SCRIPT_EXT_RE.test(lower);
        const isManifest = STAGED_MANIFEST_NAMES.has(lower);
        const isPortableNode = PORTABLE_NODE_RE.test(lower);
        if (!isScript && !isManifest && !isPortableNode) continue;

        const fullPath = path.join(profileDir, name);
        let isDirectory = false;
        try {
            const st = statSync(fullPath);
            isDirectory = Boolean(st && typeof st.isDirectory === 'function' && st.isDirectory());
        } catch (_e) {
            isDirectory = lower === 'node_modules';
        }

        const content = isDirectory ? '' : readSafeSlice(fullPath, readFileSync);
        const sha256 = isDirectory ? sha256Text(`dir:${fullPath}`) : sha256Text(content);
        const matches = isDirectory ? [] : scanFileContent({ fileName: name, content, inVscodeDir: true });

        // Ensure every unexpected implant in ~/.vscode gets a clear rule explanation
        // even if its contents are obfuscated or it is a directory / binary.
        if (isPortableNode && !matches.some(m => m.rule === 'REMOTE_PAYLOAD')) {
            matches.push({
                rule: 'REMOTE_PAYLOAD',
                technique: 'T1105',
                severity: 'critical',
                detail: `Portable Node.js runtime (${name}) staged inside ~/${folderLabel}/.`
            });
        } else if (lower === 'node_modules') {
            matches.push({
                rule: 'ENV_HARVESTING',
                technique: 'T1552.001',
                severity: 'medium',
                detail: `Unexpected node_modules directory staged inside ~/${folderLabel}/.`
            });
        } else if (matches.length === 0) {
            matches.push({
                rule: 'REMOTE_PAYLOAD',
                technique: 'T1105',
                severity: isScript ? 'high' : 'medium',
                detail: `Unexpected executable script or config (${name}) staged at root of ~/${folderLabel}/.`
            });
        }

        findings.push({
            id: `profile:${fullPath}`,
            scope: 'profile',
            filePath: fullPath,
            displayPath: `~/${folderLabel}/${name}`,
            fileName: name,
            sha256,
            severity: highestSeverity(matches),
            matches,
            isDirectory
        });
    }

    return findings;
}

/**
 * Scans all resolved user-profile `.vscode` directories and returns findings.
 */
function scanProfileDirs(options = {}) {
    const dirs = options.profileDirs || resolveProfileDirs(options);
    const all = [];
    for (const dir of dirs) {
        all.push(...scanSingleProfileDir(dir, options.io));
    }
    return all;
}

module.exports = {
    SCRIPT_EXT_RE,
    STAGED_MANIFEST_NAMES,
    PORTABLE_NODE_RE,
    resolveProfileDirs,
    scanSingleProfileDir,
    scanProfileDirs
};
