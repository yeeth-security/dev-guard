/**
 * DevGuard side pane (WebviewView provider).
 *
 * Lives in the Activity Bar under the DevGuard shield icon. Shows the verdict,
 * lets the user run a scan and change mode / marketplace, and lists the scan
 * log, removed extensions, audit log, and inventory. HTML is built in
 * `ui/paneHtml.js`; this file owns the view lifecycle and messages.
 */

const crypto = require('crypto');
const vscode = require('vscode');
const { renderPane, renderParts } = require('./paneHtml');
const { readAllowlist, addToAllowlist, removeFromAllowlist } = require('../allowlist');
const { CHECKS, readState, applyCheck, splitSettingKey, versionBucket } = require('../hardening');
const { REMOVAL_GUIDE_URL } = require('../notifier');

const VIEW_ID = 'devGuard.panel';
const MODES = ['auto', 'manual', 'warn'];
const PKGSCAN_URL = 'https://www.pkgscan.dev/';
const MAX_URL_LENGTH = 300;

/**
 * Accepts the marketplace values the pane can send:
 *   ''        default (detect from the editor)
 *   'custom'  Custom chosen, URL not typed yet
 *   https URL custom gallery URL
 * Returns the cleaned value, or null if it is not acceptable.
 */
function cleanMarketplaceValue(value) {
    if (typeof value !== 'string') return null;
    const text = value.trim();
    if (text === '' || text === 'custom') return text;
    if (text.length > MAX_URL_LENGTH) return null;
    try {
        const url = new URL(text);
        return url.protocol === 'https:' || url.protocol === 'http:' ? text : null;
    } catch (_error) {
        return null;
    }
}

/** `inspect()` for one setting key, split into section + name. Never throws. */
function inspectSetting(key) {
    const { section, name } = splitSettingKey(key);
    try {
        return vscode.workspace.getConfiguration(section).inspect(name);
    } catch (_error) {
        return undefined;
    }
}

/**
 * Writes one setting at user (Global) scope. ENG-27: never Workspace, never
 * WorkspaceFolder — an extension that rewrites repo config commits the same
 * trust violation as the attack it defends against.
 */
async function updateGlobalSetting(key, value) {
    const target = vscode.ConfigurationTarget ? vscode.ConfigurationTarget.Global : true;
    const { section, name } = splitSettingKey(key);
    await vscode.workspace.getConfiguration(section).update(name, value, target);
}

/**
 * @param {{
 *   history: ReturnType<import('../history').createHistoryStore>,
 *   audit: ReturnType<import('../audit').createAuditLog>,
 *   getStatus: () => any,
 *   runScan: () => Promise<any>,
 *   telemetry?: { record: Function }
 * }} deps
 */
function createPane({ history, audit, getStatus, runScan, telemetry }) {
    /** @type {vscode.WebviewView|null} */
    let view = null;
    let scanning = false;
    // Last write error per hardening check, so the row can show why Apply failed.
    const hardenErrors = {};
    // True once the page's script has loaded and said "ready". Before that we
    // must set the full HTML; after that we only send incremental updates so
    // scroll position, focus, and open/closed sections are never disturbed.
    let ready = false;

    function collectData() {
        // Read live on every render: these rows depend on editor settings, not
        // on DevGuard state. Errors stay attached so a failed Apply explains itself.
        const hardening = readState(inspectSetting).map(row =>
            hardenErrors[row.id] ? { ...row, error: hardenErrors[row.id] } : row
        );
        return {
            status: getStatus(),
            runs: history.listRuns(),
            removed: history.listRemoved(),
            inventory: history.getLastInventory(),
            audit: audit.list(),
            allowlist: [...readAllowlist(vscode)].sort(),
            hardening,
            scanning
        };
    }

    /** Pushes current data to the view: a full page the first time, a patch after that. */
    function refresh() {
        if (!view) return;
        const data = collectData();
        if (ready) {
            void view.webview.postMessage({ type: 'update', parts: renderParts(data) });
        } else {
            view.webview.html = renderPane({ ...data, nonce: crypto.randomBytes(16).toString('base64') });
        }
    }

    async function updateSetting(key, value) {
        const target = vscode.ConfigurationTarget ? vscode.ConfigurationTarget.Global : true;
        await vscode.workspace.getConfiguration('devGuard').update(key, value, target);
    }

    async function handleMessage(message) {
        if (!message || typeof message.type !== 'string') return;
        const id = typeof message.id === 'string' ? message.id.trim() : '';
        switch (message.type) {
            case 'ready':
                // The page script is live. From now on, patch instead of reload.
                // Re-send current data in case anything changed while it loaded.
                ready = true;
                refresh();
                break;
            case 'scan':
                if (scanning) return;
                scanning = true;
                refresh();
                try { await runScan(); } finally { scanning = false; refresh(); }
                break;
            case 'settings':
                void vscode.commands.executeCommand('workbench.action.openSettings', 'devGuard');
                break;
            case 'harden': {
                // ENG-27: one setting, one click, user scope only. applyCheck
                // refuses to write when the row is already safe.
                const check = typeof message.check === 'string' ? message.check : '';
                if (!CHECKS.some(item => item.id === check)) { refresh(); break; }
                delete hardenErrors[check];
                const result = await applyCheck(updateGlobalSetting, inspectSetting, check);
                if (result.applied) {
                    audit.record({ type: 'hardening', detail: result.row.key });
                    // No values, no paths: setting key + coarse editor version only.
                    telemetry?.record('hardening_applied', {
                        setting: result.row.key,
                        editor_version: versionBucket(vscode.version)
                    });
                    vscode.window.setStatusBarMessage(`DevGuard: ${result.row.label} set to ${result.row.recommendedLabel}`, 3000);
                } else if (!result.ok && result.error) {
                    hardenErrors[check] = result.error;
                }
                refresh();
                break;
            }
            case 'reload':
                // From the hero's reload notice: unloads removed extensions from memory.
                telemetry?.record('reload_clicked', { from: 'pane' });
                void vscode.commands.executeCommand('workbench.action.reloadWindow');
                break;
            case 'openUrl':
                if (typeof message.url === 'string' && /^https:\/\//.test(message.url)) {
                    void vscode.env.openExternal(vscode.Uri.parse(message.url));
                    // Same event the toasts record, so the funnel sees every guide open.
                    if (message.url === REMOVAL_GUIDE_URL) telemetry?.record('removal_guide_opened', { from: 'pane' });
                }
                break;
            case 'pkgscan':
                void vscode.env.openExternal(vscode.Uri.parse(PKGSCAN_URL));
                break;
            case 'copy':
                // Hash chips: copy the full SHA-256 and confirm in the status bar.
                if (typeof message.text === 'string' && /^[a-f0-9]{16,128}$/i.test(message.text)) {
                    await vscode.env.clipboard.writeText(message.text);
                    vscode.window.setStatusBarMessage('DevGuard: hash copied', 2000);
                }
                break;
            case 'setMode':
                if (MODES.includes(message.value) && message.value !== getStatus().removalMode) {
                    await updateSetting('removalMode', message.value);
                    audit.record({ type: 'mode', detail: message.value });
                    telemetry?.record('mode_changed', { mode: message.value, from: 'panel' });
                }
                break;
            case 'setMarketplace': {
                const value = cleanMarketplaceValue(message.value);
                if (value === null) {
                    vscode.window.setStatusBarMessage('DevGuard: enter a valid http(s) gallery URL', 3000);
                    refresh(); // restore the saved value in the box
                    break;
                }
                const current = String(vscode.workspace.getConfiguration('devGuard').get('marketplace', '') || '');
                if (value === current) break;
                await updateSetting('marketplace', value);
                // Only log meaningful changes: default, or a real URL (not the empty "custom" placeholder).
                if (value !== 'custom') {
                    audit.record({ type: 'marketplace', detail: value || 'default' });
                    telemetry?.record('marketplace_changed', { custom: value !== '', from: 'panel' });
                }
                break;
            }
            case 'allow':
                if (!id) return;
                {
                    // Confirm first: allowlisting a flagged extension is a real security decision.
                    const choice = await vscode.window.showWarningMessage(
                        `Allow '${id}'? DevGuard will stop flagging and removing it, even though it matches a malicious advisory.`,
                        { modal: true }, 'Allow'
                    );
                    if (choice === 'Allow') {
                        await addToAllowlist(vscode, id);
                        audit.record({ type: 'allowed', id });
                        telemetry?.record('allowlist_added', { extension_id: id });
                    }
                }
                break;
            case 'unallow':
                if (!id) return;
                await removeFromAllowlist(vscode, id);
                audit.record({ type: 'unallowed', id });
                telemetry?.record('allowlist_removed', { extension_id: id });
                break;
            default:
                break;
        }
    }

    /** @type {vscode.WebviewViewProvider} */
    const provider = {
        resolveWebviewView(webviewView) {
            view = webviewView;
            ready = false;
            view.webview.options = { enableScripts: true };
            view.webview.onDidReceiveMessage(message => { void handleMessage(message); });
            view.onDidChangeVisibility(() => { if (view && view.visible) refresh(); });
            view.onDidDispose(() => { view = null; ready = false; });
            telemetry?.record('panel_opened');
            refresh();
        }
    };

    const registration = vscode.window.registerWebviewViewProvider(VIEW_ID, provider, {
        webviewOptions: { retainContextWhenHidden: true }
    });
    // Re-render on any data or settings change, so the pane is never stale.
    const unsubscribers = [history.onChange(refresh), audit.onChange(refresh)];
    const configWatcher = vscode.workspace.onDidChangeConfiguration(e => {
        // Refresh for DevGuard's own settings and for any hardening check, so a
        // change made in the Settings UI is reflected in the rows immediately.
        if (e.affectsConfiguration('devGuard') || CHECKS.some(check => e.affectsConfiguration(check.key))) refresh();
    });

    return {
        refresh,
        /** Brings the pane into view. VS Code auto-registers `<viewId>.focus`. */
        show: () => vscode.commands.executeCommand(`${VIEW_ID}.focus`),
        dispose() {
            unsubscribers.forEach(fn => fn());
            configWatcher.dispose();
            registration.dispose();
        }
    };
}

module.exports = { VIEW_ID, createPane, cleanMarketplaceValue, inspectSetting, updateGlobalSetting };
