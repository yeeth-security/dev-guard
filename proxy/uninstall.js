/**
 * Uninstall detection and disk-level marketplace configuration recovery.
 *
 * Why this file exists:
 *   When a user uninstalls Dev-Guard, the editor's marketplace settings
 *   (`extensions.gallery.serviceUrl`, `product.json#extensionsGallery`,
 *   `workbench.html` CSP, and `devGuard.marketplace`) must be reverted from
 *   the local `127.0.0.1` proxy back to the user's previous configuration.
 *
 *   Supports both:
 *     1. Live in-session detection (`createSelfUninstallDetector`) so the
 *        running extension reverts the marketplace as soon as Uninstall is clicked.
 *     2. Standalone post-uninstall recovery (`runUninstallRestore`), invoked by
 *        `scripts/uninstall.js` (`package.json` `"vscode:uninstall"` hook) and
 *        `deactivate()`, which edits `settings.json`, `product.json`, and
 *        `workbench.html` directly on disk without needing the `vscode` API.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const RESTORE_FILENAME = 'uninstall-restore.json';
const EXTENSION_ID = 'yeeth.dev-guard';

/** Checks whether a URL string points to `127.0.0.1`, `localhost`, or `[::1]`. */
function isLoopback(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    return /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(rawUrl.trim());
}

/** Returns the path to `uninstall-restore.json` inside `globalStorageUri`. */
function getRestoreFilePath(context) {
    const dir = context && context.globalStorageUri && context.globalStorageUri.fsPath;
    return typeof dir === 'string' && dir ? path.join(dir, RESTORE_FILENAME) : null;
}

/** Infers the active profile's `settings.json` path from `.../User/globalStorage/<ext>`. */
function inferUserSettingsPath(globalStorageDir) {
    if (typeof globalStorageDir !== 'string' || !globalStorageDir) return null;
    return path.resolve(globalStorageDir, '..', '..', 'settings.json');
}

/**
 * Infers the active editor's `User` directory from `scriptDir` or `globalStorageUri`
 * so uninstall only touches the editor being uninstalled from.
 */
function inferEditorUserDir({ context, scriptDir, platform = process.platform, env = process.env, homedir = os.homedir() } = {}) {
    const storageDir = context && context.globalStorageUri && context.globalStorageUri.fsPath;
    if (typeof storageDir === 'string' && storageDir) {
        return path.resolve(storageDir, '..', '..');
    }
    const loc = String(scriptDir || '').toLowerCase();
    const base = platform === 'win32'
        ? (env.APPDATA || path.join(homedir, 'AppData', 'Roaming'))
        : platform === 'darwin'
            ? path.join(homedir, 'Library', 'Application Support')
            : (env.XDG_CONFIG_HOME || path.join(homedir, '.config'));

    if (loc.includes('.cursor')) return path.join(base, 'Cursor', 'User');
    if (loc.includes('.vscode-insiders')) return path.join(base, 'Code - Insiders', 'User');
    if (loc.includes('.vscode-oss') || loc.includes('.codium')) return path.join(base, 'VSCodium', 'User');
    if (loc.includes('.windsurf')) return path.join(base, 'Windsurf', 'User');
    if (loc.includes('.vscode')) return path.join(base, 'Code', 'User');
    return null;
}

/**
 * Discovers candidate `appRoot` directories (`.../resources/app`) for the active
 * editor from `process.resourcesPath`, `process.execPath`, or standard install
 * locations so `product.json` and `workbench.html` are always restored even if
 * `uninstall-restore.json` was missing.
 */
function inferEditorAppRoots({ appRoot, scriptDir, io = fs } = {}) {
    const roots = new Set();
    if (typeof appRoot === 'string' && appRoot) roots.add(appRoot);
    if (typeof process.resourcesPath === 'string' && process.resourcesPath) {
        roots.add(path.join(process.resourcesPath, 'app'));
    }
    if (typeof process.execPath === 'string' && process.execPath) {
        const execDir = path.dirname(process.execPath);
        roots.add(path.join(execDir, 'resources', 'app'));
        roots.add(path.resolve(execDir, '..', 'resources', 'app'));
    }
    const loc = String(scriptDir || '').toLowerCase();
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    if (!loc || loc.includes('.vscode')) {
        const vscodeProg = path.join(localAppData, 'Programs', 'Microsoft VS Code');
        roots.add(path.join(vscodeProg, 'resources', 'app'));
        try {
            if (io.existsSync(vscodeProg) && typeof io.readdirSync === 'function') {
                for (const entry of io.readdirSync(vscodeProg)) {
                    roots.add(path.join(vscodeProg, String(entry), 'resources', 'app'));
                }
            }
        } catch (_e) { /* ignore */ }
    }
    return [...roots];
}

/** Persists a small restore manifest to `globalStorageUri` for `scripts/uninstall.js`. */
function writeUninstallRestoreManifest(context, vscodeApi, state = {}, io = fs) {
    const filePath = getRestoreFilePath(context);
    if (!filePath) return null;
    try {
        const storageDir = path.dirname(filePath);
        io.mkdirSync?.(storageDir, { recursive: true });
        const usedProductJson = state.usedProductJson !== false;
        const payload = {
            appRoot: usedProductJson ? ((vscodeApi && vscodeApi.env && vscodeApi.env.appRoot) || null) : null,
            usedProductJson,
            restored: false,
            settingsPath: inferUserSettingsPath(storageDir),
            savedGalleryServiceUrl: typeof state.savedGalleryServiceUrl === 'string' ? state.savedGalleryServiceUrl : '',
            savedDevGuardMarketplace: typeof state.savedDevGuardMarketplace === 'string' ? state.savedDevGuardMarketplace : '',
            upstreamServiceUrl: typeof state.upstreamServiceUrl === 'string' ? state.upstreamServiceUrl : null
        };
        io.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
        return filePath;
    } catch (_error) {
        return null;
    }
}

function isListedInExtensionsManifest(extensionsDir, extId = EXTENSION_ID, io = fs) {
    try {
        const manifestPath = path.join(extensionsDir, 'extensions.json');
        if (!io.existsSync(manifestPath)) return null;
        const parsed = JSON.parse(io.readFileSync(manifestPath, 'utf8'));
        if (!Array.isArray(parsed)) return null;
        const target = String(extId || EXTENSION_ID).toLowerCase();
        return parsed.some(item => String(item && item.identifier && item.identifier.id || '').toLowerCase() === target);
    } catch (_error) {
        return null;
    }
}

function createSelfUninstallDetector(context, io = fs) {
    const extPath = context && typeof context.extensionPath === 'string' ? context.extensionPath : '';
    const extId = (context && context.extension && context.extension.id) || EXTENSION_ID;
    const extensionsDir = extPath ? path.dirname(extPath) : '';
    const folderName = extPath ? path.basename(extPath) : '';
    const initiallyListed = extensionsDir ? isListedInExtensionsManifest(extensionsDir, extId, io) === true : false;

    return function isSelfUninstalled() {
        if (!extPath || !extensionsDir || !folderName) return false;
        try {
            const obsoletePath = path.join(extensionsDir, '.obsolete');
            if (io.existsSync(obsoletePath)) {
                const obsolete = JSON.parse(io.readFileSync(obsoletePath, 'utf8'));
                if (obsolete && obsolete[folderName]) return true;
            }
        } catch (_error) { /* ignore malformed .obsolete */ }

        if (initiallyListed) {
            const stillListed = isListedInExtensionsManifest(extensionsDir, extId, io);
            if (stillListed === false) return true;
        }
        return false;
    };
}

function restoreMarketplaceSettingsFile(settingsPath, saved = {}, io = fs) {
    if (typeof settingsPath !== 'string' || !settingsPath) return false;
    try {
        if (!io.existsSync(settingsPath)) return false;
        const parsed = JSON.parse(io.readFileSync(settingsPath, 'utf8'));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;

        let changed = false;
        if (isLoopback(parsed['extensions.gallery.serviceUrl'])) {
            const priorGallery = saved.savedGalleryServiceUrl;
            if (typeof priorGallery === 'string' && priorGallery && !isLoopback(priorGallery)) {
                parsed['extensions.gallery.serviceUrl'] = priorGallery;
            } else {
                delete parsed['extensions.gallery.serviceUrl'];
            }
            changed = true;
        }
        if (isLoopback(parsed['devGuard.marketplace'])) {
            const priorMp = saved.savedDevGuardMarketplace;
            if (typeof priorMp === 'string' && priorMp && !isLoopback(priorMp)) {
                parsed['devGuard.marketplace'] = priorMp;
            } else {
                delete parsed['devGuard.marketplace'];
            }
            changed = true;
        }
        if (changed) {
            io.writeFileSync(settingsPath, `${JSON.stringify(parsed, null, 4)}\n`, 'utf8');
        }
        return changed;
    } catch (_error) {
        return false;
    }
}

function runUninstallRestore({ context, appRoot, scriptDir, restoreProductJsonGallery, userDirs, io = fs } = {}) {
    let dirs = Array.isArray(userDirs) ? userDirs : null;
    if (!dirs) {
        const inferred = inferEditorUserDir({ context, scriptDir });
        dirs = inferred ? [inferred] : [];
    }

    const candidateManifests = [];
    const ctxManifest = getRestoreFilePath(context);
    if (ctxManifest) candidateManifests.push(ctxManifest);
    for (const uDir of dirs) {
        candidateManifests.push(path.join(uDir, 'globalStorage', EXTENSION_ID, RESTORE_FILENAME));
    }

    const settingsTargets = new Map();
    const appRoots = new Map();
    const loadedManifests = [];
    let foundManifest = false;
    let shouldCheckAppRoots = false;

    for (const manifestPath of candidateManifests) {
        try {
            if (!io.existsSync(manifestPath)) continue;
            const data = JSON.parse(io.readFileSync(manifestPath, 'utf8'));
            if (!data || typeof data !== 'object') continue;
            foundManifest = true;
            if (data.restored === true) continue;
            loadedManifests.push({ manifestPath, data });
            if (data.settingsPath) settingsTargets.set(data.settingsPath, data);
            if (data.usedProductJson !== false) {
                shouldCheckAppRoots = true;
                if (data.appRoot) appRoots.set(data.appRoot, data.upstreamServiceUrl || null);
            }
        } catch (_error) { /* ignore unreadable manifest */ }
    }

    // If a manifest exists and was already marked `restored: true` by the live
    // extension session (`checkSelfUninstall`), exit immediately so `scripts/uninstall.js`
    // and `deactivate()` do zero disk I/O while the IDE restarts or updates.
    if (foundManifest && loadedManifests.length === 0) {
        return false;
    }

    if (!foundManifest) {
        for (const uDir of dirs) settingsTargets.set(path.join(uDir, 'settings.json'), {});
        shouldCheckAppRoots = true;
    }
    if (shouldCheckAppRoots) {
        for (const r of inferEditorAppRoots({ appRoot, scriptDir, io })) {
            if (!appRoots.has(r)) appRoots.set(r, null);
        }
    }

    let restoredAny = false;
    if (shouldCheckAppRoots && typeof restoreProductJsonGallery === 'function') {
        for (const [rootDir, fallbackUrl] of appRoots.entries()) {
            const ok = restoreProductJsonGallery({
                appRoot: rootDir,
                readFileSync: (...a) => io.readFileSync(...a),
                writeFileSync: (...a) => io.writeFileSync(...a)
            }, fallbackUrl);
            if (ok) restoredAny = true;
        }
    }
    for (const [sPath, saved] of settingsTargets.entries()) {
        if (restoreMarketplaceSettingsFile(sPath, saved, io)) restoredAny = true;
    }

    for (const { manifestPath, data } of loadedManifests) {
        try {
            io.writeFileSync(manifestPath, `${JSON.stringify({ ...data, restored: true }, null, 2)}\n`, 'utf8');
        } catch (_e) { /* ignore */ }
    }
    return restoredAny;
}

module.exports = {
    RESTORE_FILENAME,
    getRestoreFilePath,
    inferUserSettingsPath,
    inferEditorUserDir,
    inferEditorAppRoots,
    writeUninstallRestoreManifest,
    createSelfUninstallDetector,
    restoreMarketplaceSettingsFile,
    runUninstallRestore
};
