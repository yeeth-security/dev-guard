/**
 * Lifecycle controller for the local marketplace security proxy.
 *
 * Why this file exists:
 *   Connects the HTTP proxy server (`proxy/server.js`) and configuration
 *   manager (`proxy/config.js`) to the VS Code extension lifecycle, user
 *   settings, audit log, notifications, and telemetry.
 */

const {
    resolveDefaultProxyPort,
    isLoopbackUrl,
    buildProxyServiceUrl,
    loadProxyState,
    saveProxyState,
    restoreProductJsonGallery,
    resolveUpstreamMarketplace,
    applyProxyMarketplaceConfig,
    restoreProxyMarketplaceConfig
} = require('./config');
const { createMarketplaceProxy } = require('./server');
const { createSelfUninstallDetector, runUninstallRestore } = require('./uninstall');
const { readAllowlist, isAllowlisted, addToAllowlist } = require('../allowlist');

const BLOCK_MODAL_COOLDOWN_MS = 3000;
const SELF_UNINSTALL_CHECK_MS = 2000;

/**
 * Reads whether `devGuard.proxy.enabled` is turned on (default: `true`).
 */
function getProxyEnabled(vscodeApi) {
    try {
        return vscodeApi.workspace.getConfiguration('devGuard').get('proxy.enabled', true) !== false;
    } catch (_error) {
        return true;
    }
}

/**
 * Creates the marketplace proxy controller bound to the extension context.
 */
function createProxyController({ context, vscodeApi, getAdvisories, audit, telemetry, onChange, pkgscanBaseUrl, preferredPort, allowLoopbackAssets = false }) {
    let syncing = false;
    let uninstalled = false;
    let restartRequired = false;
    let uninstallCheckTimer = null;
    const recentBlockModals = new Map();
    const isSelfUninstalled = createSelfUninstallDetector(context);

    function promptIdeRestart(message, from) {
        if (!vscodeApi || !vscodeApi.window) return;
        const showFn = typeof vscodeApi.window.showWarningMessage === 'function'
            ? vscodeApi.window.showWarningMessage.bind(vscodeApi.window)
            : (typeof vscodeApi.window.showInformationMessage === 'function'
                ? vscodeApi.window.showInformationMessage.bind(vscodeApi.window)
                : null);
        if (!showFn) return;
        void Promise.resolve(showFn(message, 'Restart Now')).then(sel => {
            const picked = sel && typeof sel === 'object' ? sel.title : sel;
            if (picked === 'Restart Now' && vscodeApi.commands && typeof vscodeApi.commands.executeCommand === 'function') {
                telemetry?.record('reload_clicked', { from });
                void vscodeApi.commands.executeCommand('workbench.action.reloadWindow');
            }
        }).catch(() => {});
    }

    const proxy = createMarketplaceProxy({
        context,
        pkgscanBaseUrl,
        // TEST ONLY: lets `/asset/` reach local mock servers. Always `false` in the extension.
        allowLoopbackAssets,
        // The proxy moved to a new port because an unverified process took the
        // shared one. Re-sync so the marketplace settings point at the new port.
        onPortChanged: () => { void sync(); },
        getUpstream: () => resolveUpstreamMarketplace(context, vscodeApi),
        getAdvisories,
        isAllowlisted: id => isAllowlisted(id, readAllowlist(vscodeApi)),
        onFlaggedReadmeViewed: ({ id, version, severity, blockSource, registry, allowlisted }) => {
            // Record at most once per extension version per 24h so browsing READMEs never spams.
            // Comparing `flagged_readme_viewed` against `download_blocked` per user shows how
            // often the README warning banner convinces users not to click Install at all.
            const props = {
                extension_id: id,
                installed_version: version || 'unknown',
                severity: severity || 'high',
                block_source: blockSource || 'advisory',
                registry: registry || 'unknown',
                allowlisted: Boolean(allowlisted)
            };
            const key = `flagged_readme:${String(id || '').toLowerCase()}@${version || 'latest'}`;
            if (typeof telemetry?.recordOnce === 'function') {
                telemetry.recordOnce(key, 'flagged_readme_viewed', props);
            } else {
                telemetry?.record?.('flagged_readme_viewed', props);
            }
        },
        onBlockedDownload: ({ id, version, registry, blockSource, advisory, fromPeer }) => {
            const extKey = String(id || '').toLowerCase();
            const now = Date.now();
            if (now - (recentBlockModals.get(extKey) || 0) < BLOCK_MODAL_COOLDOWN_MS) return;

            const sev = (advisory && advisory.severity) || 'high';
            const src = blockSource || 'advisory';
            const reg = registry || 'unknown';
            const reason = (advisory && advisory.title) ? String(advisory.title).replace(/[_-]+/g, ' ') : 'Malicious package advisory';
            audit?.record({ type: 'blocked', id, version, detail: `${sev} · ${reason}` });
            try { onChange?.(); } catch (_e) { /* ignore */ }
            if (!fromPeer) {
                const blockProps = {
                    extension_id: id,
                    installed_version: version || 'unknown',
                    severity: sev,
                    block_source: src,
                    registry: reg
                };
                if (typeof telemetry?.recordOnce === 'function') {
                    telemetry.recordOnce(`block:${extKey}@${version || 'latest'}`, 'download_blocked', blockProps, 60 * 1000);
                } else {
                    telemetry?.record?.('download_blocked', blockProps);
                }
            }

            if (!vscodeApi || !vscodeApi.window || typeof vscodeApi.window.showWarningMessage !== 'function') return;
            // When multiple editor windows are open, only display the modal in the focused window.
            if (vscodeApi.window.state && typeof vscodeApi.window.state.focused === 'boolean' && !vscodeApi.window.state.focused) return;
            recentBlockModals.set(extKey, now);

            const reportUrl = advisory && advisory.permalink ? advisory.permalink : null;
            const detail = `Dev-Guard prevented '${id}${version ? `@${version}` : ''}' from being downloaded and installed because it was flagged on pkgscan.dev (${reason}).\n\n`
                + 'Keeping this extension blocked is strongly recommended. Only allowlist it if you trust the publisher and want to permit installation on retry.';
            const allowBtn = { title: 'Allowlist Extension' };
            const reportBtn = { title: 'View Report' };
            const cancelBtn = { title: 'Cancel Install', isCloseAffordance: true };
            const buttons = reportUrl ? [allowBtn, reportBtn, cancelBtn] : [allowBtn, cancelBtn];

            void vscodeApi.window.showWarningMessage(
                `Malicious Extension Blocked: ${id}${version ? `@${version}` : ''}`,
                { modal: true, detail },
                ...buttons
            ).then(async sel => {
                const picked = sel && typeof sel === 'object' ? sel.title : sel;
                const baseDecisionProps = {
                    extension_id: id,
                    installed_version: version || 'unknown',
                    severity: sev,
                    block_source: src,
                    registry: reg
                };
                if (picked === 'Allowlist Extension') {
                    await addToAllowlist(vscodeApi, id);
                    audit?.record({ type: 'allowed', id });
                    telemetry?.record('allowlist_added', { extension_id: id, from: 'block_modal' });
                    telemetry?.record('blocked_modal_decision', {
                        ...baseDecisionProps,
                        decision: 'allowlist',
                        refused_install: false
                    });
                    try { onChange?.(); } catch (_e) { /* ignore */ }
                    vscodeApi.window.showInformationMessage?.(
                        `'${id}' has been added to devGuard.allowlist. Click Install again if you still want to install it.`
                    );
                } else if (picked === 'View Report') {
                    telemetry?.record('blocked_modal_decision', {
                        ...baseDecisionProps,
                        decision: 'view_report',
                        refused_install: true
                    });
                    telemetry?.record('pkgscan_opened', {
                        source: 'blocked_modal',
                        extension_id: id,
                        installed_version: version || 'unknown',
                        registry: reg
                    });
                    if (reportUrl && vscodeApi.env) {
                        void vscodeApi.env.openExternal(vscodeApi.Uri.parse(reportUrl));
                    }
                } else {
                    telemetry?.record('blocked_modal_decision', {
                        ...baseDecisionProps,
                        decision: 'cancel',
                        refused_install: true
                    });
                }
            });
        },
        onUnscannedInstall: async ({ id, version, registry, scanStatus, reportUrl, hasPeers, fromPeer }) => {
            if (!vscodeApi || !vscodeApi.window || typeof vscodeApi.window.showWarningMessage !== 'function') {
                return 'continue';
            }
            const isFocused = !vscodeApi.window.state || typeof vscodeApi.window.state.focused !== 'boolean' || vscodeApi.window.state.focused;
            if (!isFocused && (fromPeer || hasPeers)) {
                return 'defer';
            }
            const scanBtn = { title: 'Scan on pkgscan.dev' };
            const continueBtn = { title: 'Continue Install (At Your Own Risk)' };
            const cancelBtn = { title: 'Cancel Install', isCloseAffordance: true };
            const detail = `'${id}' (version ${version || 'latest'}) has not been scanned on pkgscan.dev yet.\n\n`
                + 'Would you like to open pkgscan.dev to start a security scan for this version, or continue with the installation at your own risk?';

            const sel = await vscodeApi.window.showWarningMessage(
                `Extension Not Scanned: ${id}${version ? `@${version}` : ''}`,
                { modal: true, detail },
                scanBtn,
                continueBtn,
                cancelBtn
            );
            const picked = sel && typeof sel === 'object' ? sel.title : sel;
            const baseProps = {
                extension_id: id,
                installed_version: version || 'unknown',
                registry: registry || 'unknown',
                scan_status: scanStatus || 'unscanned'
            };
            if (picked === 'Continue Install (At Your Own Risk)') {
                audit?.record({ type: 'allowed', id, version, detail: 'unscanned · installed at own risk' });
                telemetry?.record('unscanned_install_decision', { ...baseProps, decision: 'continue', refused_install: false });
                try { onChange?.(); } catch (_e) { /* ignore */ }
                return 'continue';
            }
            if (picked === 'Scan on pkgscan.dev') {
                audit?.record({ type: 'blocked', id, version, detail: 'unscanned · opened pkgscan.dev' });
                telemetry?.record('unscanned_install_decision', { ...baseProps, decision: 'scan', refused_install: true });
                telemetry?.record('pkgscan_opened', {
                    source: 'unscanned_modal',
                    extension_id: id,
                    installed_version: version || 'unknown',
                    registry: registry || 'unknown'
                });
                try { onChange?.(); } catch (_e) { /* ignore */ }
                if (reportUrl && vscodeApi.env && typeof vscodeApi.env.openExternal === 'function') {
                    void vscodeApi.env.openExternal(vscodeApi.Uri.parse(reportUrl));
                }
                return 'scan';
            }
            audit?.record({ type: 'blocked', id, version, detail: 'unscanned · cancelled' });
            telemetry?.record('unscanned_install_decision', { ...baseProps, decision: 'cancel', refused_install: true });
            try { onChange?.(); } catch (_e) { /* ignore */ }
            return 'cancel';
        },
        onUnscannedDecision: ({ id, version, decision }) => {
            if (!id) return;
            if (decision === 'continue') {
                audit?.record({ type: 'allowed', id, version, detail: 'unscanned · installed at own risk' });
            } else if (decision === 'scan') {
                audit?.record({ type: 'blocked', id, version, detail: 'unscanned · opened pkgscan.dev' });
            } else {
                audit?.record({ type: 'blocked', id, version, detail: 'unscanned · cancelled' });
            }
            try { onChange?.(); } catch (_e) { /* ignore */ }
        }
    });

    function clearUninstallWatcher() {
        if (uninstallCheckTimer) {
            clearInterval(uninstallCheckTimer);
            uninstallCheckTimer = null;
        }
    }

    /**
     * Checks if Dev-Guard itself has been uninstalled (marked in `.obsolete` or
     * removed from `extensions.json`) and immediately stops the proxy, reverts
     * the marketplace settings back to what the user had before, and prompts
     * the user to restart the IDE.
     */
    async function checkSelfUninstall() {
        if (uninstalled) return true;
        if (!isSelfUninstalled()) return false;
        uninstalled = true;
        restartRequired = true;
        clearUninstallWatcher();
        await proxy.stop();
        await restoreProxyMarketplaceConfig(context, vscodeApi);
        runUninstallRestore({
            context,
            appRoot: vscodeApi && vscodeApi.env && vscodeApi.env.appRoot,
            restoreProductJsonGallery
        });
        promptIdeRestart(
            'Dev-Guard was uninstalled and restored your previous marketplace settings. Restart the IDE to reconnect to the extension marketplace.',
            'proxy_uninstall_prompt'
        );
        try { onChange?.(); } catch (_e) { /* ignore */ }
        return true;
    }

    async function sync() {
        if (syncing || uninstalled) return;
        if (await checkSelfUninstall()) return;
        syncing = true;
        try {
            const enabled = getProxyEnabled(vscodeApi);
            const upstream = resolveUpstreamMarketplace(context, vscodeApi);
            if (enabled) {
                const targetPort = preferredPort !== undefined ? preferredPort : resolveDefaultProxyPort(vscodeApi && vscodeApi.env);
                const port = await proxy.start(targetPort);
                const applied = await applyProxyMarketplaceConfig(context, vscodeApi, port, upstream.serviceUrl);
                if (!uninstallCheckTimer) {
                    uninstallCheckTimer = setInterval(() => { void checkSelfUninstall(); }, SELF_UNINSTALL_CHECK_MS);
                    if (typeof uninstallCheckTimer.unref === 'function') uninstallCheckTimer.unref();
                }
                if (typeof telemetry?.recordState === 'function') {
                    telemetry.recordState('proxy_status', 'proxy_status', {
                        enabled: true,
                        running: proxy.isRunning(),
                        registry: upstream.registry || 'unknown',
                        config_method: applied && applied.usedProductJson ? 'product_json' : 'settings'
                    });
                }
                if (applied && applied.restartRequired) {
                    restartRequired = true;
                    promptIdeRestart(
                        'Dev-Guard configured the local marketplace security proxy. Restart the IDE so marketplace extensions are routed through the proxy and protected.',
                        'proxy_install_prompt'
                    );
                }
            } else {
                clearUninstallWatcher();
                restartRequired = false;
                await proxy.stop();
                const restored = await restoreProxyMarketplaceConfig(context, vscodeApi);
                if (typeof telemetry?.recordState === 'function') {
                    telemetry.recordState('proxy_status', 'proxy_status', {
                        enabled: false,
                        running: false,
                        registry: upstream.registry || 'unknown',
                        config_method: 'disabled'
                    });
                }
                if (restored && restored.restartRequired) {
                    promptIdeRestart(
                        'Dev-Guard disabled the local marketplace proxy and restored your previous marketplace settings. Restart the IDE to apply the change.',
                        'proxy_disable_prompt'
                    );
                }
            }
        } catch (error) {
            console.warn('Could not sync marketplace proxy:', error);
        } finally {
            syncing = false;
            try { onChange?.(); } catch (_e) { /* ignore */ }
        }
    }

    async function setEnabled(enabled, from = 'panel') {
        const next = Boolean(enabled);
        const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
        await vscodeApi.workspace.getConfiguration('devGuard').update('proxy.enabled', next, target);
        audit?.record({ type: 'proxy', detail: next ? 'enabled' : 'disabled' });
        telemetry?.record('proxy_toggled', { enabled: next, from });
        await sync();
    }

    async function setUpstreamMarketplace(value) {
        const state = loadProxyState(context);
        if (getProxyEnabled(vscodeApi) && proxy.isRunning() && value !== 'custom' && !isLoopbackUrl(value)) {
            await saveProxyState(context, { ...state, savedDevGuardMarketplace: value });
            const upstream = resolveUpstreamMarketplace(context, vscodeApi);
            await applyProxyMarketplaceConfig(context, vscodeApi, proxy.getPort(), upstream.serviceUrl);
            try { onChange?.(); } catch (_e) { /* ignore */ }
            return;
        }
        const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
        await vscodeApi.workspace.getConfiguration('devGuard').update('marketplace', value, target);
    }

    function getStatus() {
        const enabled = getProxyEnabled(vscodeApi);
        const running = proxy.isRunning();
        const port = proxy.getPort();
        const upstream = resolveUpstreamMarketplace(context, vscodeApi);
        return {
            proxyEnabled: enabled,
            proxyRunning: running,
            proxyNeedsRestart: Boolean((enabled && restartRequired) || uninstalled),
            proxyUrl: running && port ? buildProxyServiceUrl(port) : null,
            upstreamUrl: upstream.serviceUrl
        };
    }

    function deactivate() {
        clearUninstallWatcher();
        if (!uninstalled && isSelfUninstalled()) {
            uninstalled = true;
            runUninstallRestore({
                context,
                appRoot: vscodeApi && vscodeApi.env && vscodeApi.env.appRoot,
                restoreProductJsonGallery
            });
        }
        if (typeof proxy.stopSync === 'function') {
            proxy.stopSync();
        } else {
            void proxy.stop();
        }
    }

    return {
        sync,
        setEnabled,
        setUpstreamMarketplace,
        getStatus,
        checkSelfUninstall,
        deactivate,
        isRunning: () => proxy.isRunning(),
        getPort: () => proxy.getPort(),
        dispose() {
            deactivate();
        }
    };
}

module.exports = {
    getProxyEnabled,
    createProxyController
};
