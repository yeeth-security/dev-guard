/**
 * Allowlist and "is it really still installed?" helpers.
 *
 * Why this file exists:
 *   In `auto` removal mode DevGuard keeps uninstalling a flagged extension
 *   every time the user reinstalls it. The only way to stop that is to add
 *   the extension ID to the `devGuard.allowlist` setting. This file owns
 *   reading and updating that list.
 *
 *   It also tells a *reinstall* apart from a *pending reload*. After an
 *   uninstall, VS Code keeps the extension in `vscode.extensions.all` until
 *   the window reloads. If we only looked at that list we would try to
 *   uninstall the same extension every 5 minutes and spam the user. So we
 *   check the disk instead: a reinstall recreates the folder, a pending
 *   reload does not (or lists it in the host's `.obsolete` file).
 *
 * No `vscode` import at module level, so it is easy to unit test.
 */

const fs = require('fs');
const path = require('path');

const ALLOWLIST_SETTING = 'allowlist';

/** Lower-cases and de-duplicates a raw setting value. */
function normalizeAllowlist(raw) {
    const ids = Array.isArray(raw) ? raw : [];
    return new Set(ids.filter(id => typeof id === 'string' && id.trim()).map(id => id.trim().toLowerCase()));
}

/** Reads `devGuard.allowlist` from settings. Never throws. */
function readAllowlist(vscodeApi) {
    try {
        return normalizeAllowlist(vscodeApi.workspace.getConfiguration('devGuard').get(ALLOWLIST_SETTING, []));
    } catch (_error) {
        return new Set();
    }
}

function isAllowlisted(extensionId, allowlist) {
    return allowlist instanceof Set && allowlist.has(String(extensionId || '').toLowerCase());
}

/** Writes the allowlist to the user's global settings. */
async function writeAllowlist(vscodeApi, ids) {
    const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
    await vscodeApi.workspace.getConfiguration('devGuard').update(ALLOWLIST_SETTING, [...ids].sort(), target);
}

async function addToAllowlist(vscodeApi, extensionId) {
    const ids = readAllowlist(vscodeApi);
    ids.add(String(extensionId).toLowerCase());
    await writeAllowlist(vscodeApi, ids);
}

async function removeFromAllowlist(vscodeApi, extensionId) {
    const ids = readAllowlist(vscodeApi);
    ids.delete(String(extensionId).toLowerCase());
    await writeAllowlist(vscodeApi, ids);
}

/**
 * True when the extension's files are still on disk and not marked obsolete.
 * False means "already uninstalled, waiting for a window reload".
 * @param {{extensionPath?: string}} extension
 * @param {{existsSync?: Function, readFileSync?: Function}} [io] injectable for tests
 */
function isStillOnDisk(extension, io = {}) {
    const existsSync = io.existsSync || fs.existsSync;
    const readFileSync = io.readFileSync || fs.readFileSync;
    const extensionPath = extension && extension.extensionPath;
    if (!extensionPath) return true; // Unknown path: assume installed so we never miss a real threat.

    try {
        if (!existsSync(path.join(extensionPath, 'package.json'))) return false;
    } catch (_error) {
        return true;
    }

    // VS Code writes `<extensionsDir>/.obsolete` as `{ "<folderName>": true }`
    // for folders it could not delete yet (common on Windows file locks).
    try {
        const obsolete = JSON.parse(readFileSync(path.join(path.dirname(extensionPath), '.obsolete'), 'utf8'));
        return !obsolete[path.basename(extensionPath)];
    } catch (_error) {
        return true; // No .obsolete file (or unreadable) → treat as installed.
    }
}

/** Drops allowlisted and already-uninstalled findings. */
function filterLiveFindings(findings, allowlist, io) {
    return (Array.isArray(findings) ? findings : []).filter(f =>
        f && f.extension && !isAllowlisted(f.extension.id, allowlist) && isStillOnDisk(f.extension, io)
    );
}

module.exports = {
    ALLOWLIST_SETTING,
    normalizeAllowlist,
    readAllowlist,
    isAllowlisted,
    addToAllowlist,
    removeFromAllowlist,
    isStillOnDisk,
    filterLiveFindings
};
