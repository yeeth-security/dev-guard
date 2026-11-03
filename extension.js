/**
 * Extension Security Auditor for VS Code-compatible IDEs
 *
 * @fileoverview Scans and monitors installed extensions against the pkgscan.dev
 *               advisories feed. The pkgscan feed is the only advisory source.
 *
 * @description Runs on the VS Code extension API (VS Code, Cursor, Windsurf,
 *             VSCodium, and other forks):
 *             - Polls pkgscan.dev every 5 minutes (with jitter, ETag, and backoff)
 *             - Keeps a persistent sync pointer so advisories posted while the
 *               editor was closed are never missed
 *             - Filters advisories by the active editor's marketplace registry
 *               (while checking sideloaded VSIX extensions against all registries)
 *             - Supports `auto` (default), `manual`, and `warn` removal modes
 *               with a persistent notification ledger so users are never spammed
 */

const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { createTelemetry, bucketCount, bucketDuration } = require('./telemetry');
const {
    loadSyncState,
    saveSyncState,
    shouldForceFullSync,
    recordSyncSuccess,
    recordSyncFailure
} = require('./advisories/state');
const {
    resolveEditorRegistry,
    registryFromGalleryConfig,
    loadExtensionProvenance,
    isRegistryAndPlatformMatch
} = require('./advisories/registry');
const {
    mergeAdvisories,
    fetchPkgscanAdvisories
} = require('./advisories/sync');
const { createAdvisoryMonitor } = require('./monitor');
const { createHistoryStore, hashExtensions, hashAdvisorySet, hashInventory } = require('./history');
const { createPane, inspectSetting } = require('./ui/pane');
const { notifyUnmetHealthChecks } = require('./hardening');
const { readAllowlist, filterLiveFindings } = require('./allowlist');
const { createAuditLog, scanAfterInstall } = require('./audit');
const {
    severityRank,
    showAutoModeDisclosureOnce,
    notifyAuditError,
    handleAuditFindings
} = require('./notifier');
const { createProxyController } = require('./proxy');
const { isLoopbackUrl, loadProxyState } = require('./proxy/config');

// The pkgscan.dev advisories feed is the only advisory source. See ENG-25.
// The community blocklist file malicious.json stays at its public URL for
// clients published before 0.1.1. This version does not read it.
const RECENT_SYNC_REUSE_MS = 4 * 60 * 1000; // Reuse cache on change events within 4 min of a poll
let latestAdvisories = null;
let activeProxyController = null;
let activeTelemetry = null;

function getRemovalMode() {
    try {
        const raw = vscode.workspace.getConfiguration('devGuard').get('removalMode', 'auto');
        return raw === 'manual' || raw === 'warn' ? raw : 'auto';
    } catch (_error) {
        return 'auto';
    }
}

/**
 * This function is called when your extension is activated.
 * The 'activationEvents' in package.json determine when this runs.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Extension Security Auditor is now active!');

    const telemetry = createTelemetry(context);
    activeTelemetry = telemetry;
    const outputChannel = vscode.window.createOutputChannel('Extension Security Auditor');
    showAutoModeDisclosureOnce(context, vscode, getRemovalMode(), telemetry);

    // How many Scan log / Audit log entries to keep. Read on every use so a
    // settings change applies without a reload.
    const getHistoryLimit = () => vscode.workspace.getConfiguration('devGuard').get('historyLimit');

    // Scan history + hashes + removed list. Feeds the side pane.
    const history = createHistoryStore(context, { getLimit: getHistoryLimit });

    // Audit log: allowlist changes, DevGuard removals, installs/uninstalls, setting changes.
    // Diff installed extensions now (catches changes made while the editor was
    // closed) and again whenever the extension list changes.
    const audit = createAuditLog(context, { getLimit: getHistoryLimit });
    audit.syncInstalled(vscode.extensions.all);

    // Local marketplace proxy: starts immediately on activation so gallery
    // queries, README scan headers, and advisory download blocks are ready.
    let pane = null;
    const proxyController = createProxyController({
        context,
        vscodeApi: vscode,
        getAdvisories: () => getCachedAdvisories(context),
        audit,
        telemetry,
        onChange: () => pane?.refresh()
    });
    activeProxyController = proxyController;
    const initialProxySync = proxyController.sync();
    telemetry.recordOnce('daily_activated', 'activated', {
        mode: getRemovalMode(),
        proxy_enabled: proxyController.getStatus().proxyEnabled
    });
    const proxyConfigWatcher = vscode.workspace.onDidChangeConfiguration(e => {
        if (e.affectsConfiguration('devGuard.proxy.enabled')) {
            void proxyController.sync();
        }
    });

    // Background monitor: jittered startup check + 5-minute poll loop + focus/change listeners.
    const monitor = createAdvisoryMonitor({
        vscodeApi: vscode,
        runAudit: trigger => checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger, history, audit)
    });
    monitor.start();

    // When an extension is installed or updated, scan right away (no debounce)
    // and write the outcome for that extension into the audit log. Also check
    // if Dev-Guard itself was uninstalled so the marketplace setting is reverted.
    const auditWatcher = vscode.extensions.onDidChange(() => {
        void proxyController.checkSelfUninstall();
        const events = audit.syncInstalled(vscode.extensions.all);
        const added = events.filter(e => e.type === 'installed' || e.type === 'updated');
        if (added.length > 0) void scanAfterInstall(monitor, audit, added);
    });

    // Side pane in the Activity Bar (shield icon). "DevGuard: Show Panel" focuses it.
    pane = createPane({
        history,
        audit,
        telemetry,
        getStatus: () => getPaneStatus(context, proxyController),
        setProxy: enabled => proxyController.setEnabled(enabled, 'panel'),
        setUpstreamMarketplace: value => proxyController.setUpstreamMarketplace(value),
        runScan: () => {
            telemetry.record('manual_scan_triggered', { from: 'panel' });
            return monitor.executeCycle('manual');
        }
    });

    // Warn the user on startup if any editor health check items (or the proxy) are not met,
    // and record the user's deduplicated editor security posture once proxy sync finishes.
    void Promise.resolve(initialProxySync).finally(() => {
        const proxyStatus = proxyController.getStatus();
        notifyUnmetHealthChecks({
            inspectFn: inspectSetting,
            appName: vscode.env && vscode.env.appName,
            editorVersion: vscode.version,
            proxyEnabled: proxyStatus.proxyEnabled,
            proxyNeedsRestart: proxyStatus.proxyNeedsRestart,
            showWarning: (msg, ...btns) => vscode.window.showWarningMessage(msg, ...btns),
            onOpenPane: () => pane.show(),
            telemetry
        });
    });

    // One handler, two command IDs.
    //   - `devGuard.checkExtensions` is the new "DevGuard: ..." command.
    //   - `extension-security-auditor.checkExtensions` is the old ID. We keep it
    //     so existing keybindings, tasks, and scripts keep working.
    const runManualCheck = () => {
        telemetry.record('manual_scan_triggered');
        void vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'dev-guard: checking installed extensions…',
                cancellable: false
            },
            () => monitor.executeCycle('manual')
        );
    };
    const commandDisposables = [
        'devGuard.checkExtensions',
        'extension-security-auditor.checkExtensions'
    ].map(commandId => vscode.commands.registerCommand(commandId, runManualCheck));
    commandDisposables.push(
        vscode.commands.registerCommand('devGuard.showPanel', () => pane.show()),
        vscode.commands.registerCommand('devGuard.toggleProxy', () => {
            const next = !proxyController.getStatus().proxyEnabled;
            void proxyController.setEnabled(next, 'command');
        })
    );

    context.subscriptions.push(monitor, outputChannel, pane, proxyController, proxyConfigWatcher, auditWatcher, ...commandDisposables);
    context.subscriptions.push({ dispose: () => { telemetry.dispose(); } });
}

/**
 * Which marketplace to filter advisories by.
 *
 * `devGuard.marketplace` is either empty (default: detect the editor's gallery
 * from product.json) or a custom gallery URL. A custom URL is mapped to a
 * pkgscan registry by host. Unknown hosts give `registry: null`, which means
 * "check against every marketplace" — safer than filtering on a slug pkgscan
 * does not know, which would match nothing.
 */
function resolveRegistry(context) {
    const detected = resolveEditorRegistry({
        appRoot: vscode.env.appRoot,
        appName: vscode.env.appName,
        uriScheme: vscode.env.uriScheme
    });
    let raw = '';
    try {
        raw = String(vscode.workspace.getConfiguration('devGuard').get('marketplace', '') || '').trim();
    } catch (_error) {
        raw = '';
    }
    // When the local proxy is active, `devGuard.marketplace` holds the local
    // loopback URL; read the user's saved upstream marketplace preference instead.
    if (isLoopbackUrl(raw)) {
        raw = (context && loadProxyState(context).savedDevGuardMarketplace) || '';
    }
    // "custom" is stored when the user picked Custom in the pane but has not typed a URL yet.
    const custom = raw !== '' && raw !== 'auto';
    const hasUrl = custom && /^https?:\/\//i.test(raw);
    return {
        registry: hasUrl ? registryFromGalleryConfig({ serviceUrl: raw }) : detected.registry,
        method: hasUrl ? 'custom URL' : detected.method,
        detected: detected.registry,
        marketplaceMode: custom ? 'custom' : 'default',
        marketplaceUrl: hasUrl ? raw : ''
    };
}

/**
 * Snapshot of current state for the side pane's Status section.
 * Reads only cached values, so it is safe to call on every render.
 */
/**
 * Extension IDs DevGuard removed during THIS extension-host session.
 * An uninstalled extension's code stays loaded until the window reloads, so
 * these are "pending reload". Deliberately in memory, not globalState: a
 * reload restarts the host, which empties the set — exactly when the threat
 * is actually gone. (We cannot use `vscode.extensions.all` for this: VS Code
 * drops an uninstalled extension from that list right away, even though it
 * is still running.)
 */
const removedThisSession = new Set();

/**
 * Findings already sent as `malicious_found` telemetry during THIS session.
 * Key: `<extensionId lower-case>@<installedVersion>`.
 *
 * Why this exists: an audit cycle runs at startup, every ~5 minutes, on focus,
 * on extension change, and on manual scans. A finding can stay live for many
 * cycles (failed uninstall, `warn` / `manual` mode, reinstall loop). Without
 * this set, the same finding was re-sent on every cycle. Only the telemetry
 * call is deduped. Notifier, auto-uninstall, history, and output channel
 * still run every cycle.
 *
 * In memory on purpose (simplest option). A window reload reports it once more.
 * A new version of the same extension is a new key, so it is reported once.
 */
const reportedFindings = new Set();

function getPaneStatus(context, proxyController) {
    const { registry, method, detected, marketplaceMode, marketplaceUrl } = resolveRegistry(context);
    const state = loadSyncState(context);
    const proxyStatus = proxyController ? proxyController.getStatus() : { proxyEnabled: true, proxyRunning: false, proxyUrl: null };
    return {
        pendingReload: removedThisSession.size,
        registry,
        registryMethod: method,
        detectedRegistry: detected,
        marketplaceMode,
        marketplaceUrl,
        removalMode: getRemovalMode(),
        lastSyncAt: state.lastSuccessAt || null,
        failureCount: state.failureCount || 0,
        pointer: state.pointer || null,
        ...proxyStatus
    };
}

function getCachedAdvisories(context) {
    if (Array.isArray(latestAdvisories)) return latestAdvisories;
    const cache = readCache(getStoragePath(context, 'pkgscan-advisories-cache.json'), 'entries');
    latestAdvisories = cache && Array.isArray(cache.entries) ? cache.entries : [];
    return latestAdvisories;
}

function getStoragePath(context, fileName) {
    try {
        if (context.globalStorageUri && context.globalStorageUri.fsPath) {
            fs.mkdirSync(context.globalStorageUri.fsPath, { recursive: true });
            return path.join(context.globalStorageUri.fsPath, fileName);
        }
    } catch (error) {
        console.warn('Could not prepare global storage directory:', error);
    }
    return path.join(context.extensionPath, `.${fileName}`);
}

function readCache(cacheFilePath, field) {
    try {
        if (!fs.existsSync(cacheFilePath)) return null;
        const parsed = JSON.parse(fs.readFileSync(cacheFilePath, 'utf8'));
        return parsed && Array.isArray(parsed[field]) ? parsed : null;
    } catch (error) {
        console.warn(`Could not read cache ${cacheFilePath}:`, error);
        return null;
    }
}

function writeCache(cacheFilePath, value) {
    try {
        fs.writeFileSync(cacheFilePath, JSON.stringify(value), 'utf8');
    } catch (error) {
        console.warn(`Could not write cache ${cacheFilePath}:`, error);
    }
}

/**
 * Syncs pkgscan.dev advisories using the persisted pointer in `advisories/state.js`.
 */
async function getPkgscanAdvisories(context, { trigger = 'poll', registry = null, telemetry } = {}) {
    const cacheFilePath = getStoragePath(context, 'pkgscan-advisories-cache.json');
    const cache = readCache(cacheFilePath, 'entries');
    const state = loadSyncState(context);
    const now = Date.now();
    const hasCached = Boolean(cache && cache.entries.length > 0);

    // On rapid extension-change events, reuse a very fresh sync instead of re-polling.
    if (trigger === 'change' && hasCached && state.lastSuccessAt && (now - state.lastSuccessAt) < RECENT_SYNC_REUSE_MS) {
        latestAdvisories = cache.entries;
        return { entries: cache.entries, source: 'pkgscan.dev cache', stale: false, state };
    }

    const registryChanged = Boolean(cache && (cache.registry || null) !== (registry || null));
    let full = shouldForceFullSync(state, now, hasCached) || registryChanged;

    try {
        let result = await fetchPkgscanAdvisories({ pointer: state.pointer, full, registry, etag: state.etag });
        if (!full && result.exceededPageLimit) {
            full = true;
            result = await fetchPkgscanAdvisories({ pointer: null, full: true, registry, etag: null });
        }
        if (result.notModified && hasCached) {
            const nextState = recordSyncSuccess(state, { items: [], full: false, etag: result.etag, minWaitMs: result.minWaitMs, now });
            saveSyncState(context, nextState);
            latestAdvisories = cache.entries;
            return { entries: cache.entries, source: 'pkgscan.dev (304)', stale: false, state: nextState };
        }
        const entries = full ? result.entries : mergeAdvisories(cache ? cache.entries : [], result.entries);
        const nextState = recordSyncSuccess(state, { items: result.rawItems, full, etag: result.etag, minWaitMs: result.minWaitMs, now });
        writeCache(cacheFilePath, { timestamp: now, registry: registry || null, entries });
        saveSyncState(context, nextState);
        latestAdvisories = entries;
        return { entries, source: 'pkgscan.dev', stale: false, state: nextState };
    } catch (error) {
        console.warn('Failed to fetch advisories from pkgscan.dev:', error);
        const failedState = recordSyncFailure(state);
        saveSyncState(context, failedState);
        telemetry?.record('poll_error', { trigger, kind: 'pkgscan_fetch_failed' });
        if (hasCached) {
            latestAdvisories = cache.entries;
            return { entries: cache.entries, source: 'pkgscan.dev cache (stale)', stale: true, state: failedState };
        }
        return { entries: [], source: 'none', stale: true, state: failedState };
    }
}

/**
 * Matches installed extensions against advisory entries by ID, version,
 * marketplace registry, and target platform.
 */
function findMatchingAdvisories(extensions, entries, provenanceMap, editorRegistry) {
    const byId = new Map();
    for (const entry of entries) {
        if (!entry || !entry.extensionId) continue;
        const key = entry.extensionId.toLowerCase();
        if (!byId.has(key)) byId.set(key, []);
        byId.get(key).push(entry);
    }

    const matches = [];
    for (const extension of extensions) {
        if (!extension || !extension.id) continue;
        const candidates = byId.get(extension.id.toLowerCase());
        if (!candidates) continue;

        const installedVersion = extension.packageJSON && extension.packageJSON.version;
        const extProv = provenanceMap.get(extension.id.toLowerCase());
        const applicable = candidates.filter(entry => {
            const versionOk = entry.version === '*' || !installedVersion || entry.version === installedVersion;
            return versionOk && isRegistryAndPlatformMatch(entry, extension, extProv, editorRegistry);
        });
        if (applicable.length === 0) continue;

        applicable.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
        matches.push({ extension, advisory: applicable[0] });
    }
    return matches;
}

function classifySource(source) {
    const value = String(source || '');
    return value.includes('pkgscan') ? 'pkgscan' : 'none';
}

/**
 * Runs one audit cycle: resolves marketplace, syncs advisories, matches installed
 * extensions, logs to the reused output channel, and invokes the notifier.
 */
async function checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger = 'startup', history = null, audit = null) {
    const allExtensions = vscode.extensions.all || [];
    const startedAt = Date.now();
    const removalMode = getRemovalMode();

    try {
        const { registry: editorRegistry } = resolveRegistry(context);
        const provenanceMap = loadExtensionProvenance(allExtensions);
        const hasNonGallery = allExtensions.some(ext => {
            if (!ext || (ext.packageJSON && ext.packageJSON.isBuiltin)) return false;
            const prov = provenanceMap.get(String(ext.id || '').toLowerCase());
            return !prov || prov.source !== 'gallery';
        });
        // Cursor's marketplace mirrors Open VSX, so when `editorRegistry` is
        // `cursor-marketplace` we fetch unfiltered advisories and match both
        // `cursor-marketplace` and `openvsx` client-side.
        const queryRegistry = editorRegistry && editorRegistry !== 'cursor-marketplace' && !hasNonGallery ? editorRegistry : null;

        const pkgscan = await getPkgscanAdvisories(context, { trigger, registry: queryRegistry, telemetry });
        const entries = pkgscan.entries;
        const source = pkgscan.source;
        const stale = pkgscan.stale;

        if (entries.length === 0) {
            telemetry?.record('audit_error', { trigger, kind: 'no_advisory_data' });
            return pkgscan.state;
        }

        // Drop allowlisted extensions and ones already uninstalled (waiting for
        // reload). What is left is a real, live threat — including reinstalls,
        // which auto mode removes again every time.
        const matched = findMatchingAdvisories(allExtensions, entries, provenanceMap, editorRegistry);
        const found = filterLiveFindings(matched, readAllowlist(vscode));
        const skipped = matched.length - found.length;
        const duration = bucketDuration(Date.now() - startedAt);
        const installedBucket = bucketCount(allExtensions.length);
        const auditProps = { trigger, duration, installed: installedBucket, findings: found.length, source: classifySource(source), stale: Boolean(stale) };
        const pollProps = { trigger, duration, findings: found.length, mode: removalMode, stale: Boolean(stale) };

        // Avoid blasting identical clean poll events every 5 minutes (288x/day per open window).
        // Always record immediately when findings exist, when the feed is stale, or on manual/install checks;
        // for clean background/startup polls, record at most once per 24h heartbeat.
        if (found.length > 0 || stale || trigger === 'manual' || trigger === 'install') {
            telemetry?.record('audit_completed', auditProps);
            telemetry?.record('poll_completed', pollProps);
        } else if (typeof telemetry?.recordOnce === 'function') {
            telemetry.recordOnce(`clean_audit:${trigger === 'startup' ? 'startup' : 'poll'}`, 'audit_completed', auditProps);
            telemetry.recordOnce(`clean_poll:${trigger === 'startup' ? 'startup' : 'poll'}`, 'poll_completed', pollProps);
        } else {
            telemetry?.record('audit_completed', auditProps);
            telemetry?.record('poll_completed', pollProps);
        }

        for (const { extension, advisory } of found) {
            const installedVersion = (extension.packageJSON && extension.packageJSON.version) || 'unknown';
            const reportKey = `${String(extension.id || '').toLowerCase()}@${installedVersion}`;
            if (reportedFindings.has(reportKey)) continue;
            reportedFindings.add(reportKey);
            const sev = advisory.severity || 'unknown';
            const foundProps = {
                extension_id: extension.id,
                severity: sev,
                source: 'pkgscan',
                installed_version: installedVersion
            };
            if (typeof telemetry?.recordOnce === 'function') {
                telemetry.recordOnce(`malicious_found:${reportKey}:${sev}`, 'malicious_found', foundProps);
            } else {
                telemetry?.record('malicious_found', foundProps);
            }
        }

        if (found.length > 0 || trigger === 'manual') {
            if (trigger === 'manual') outputChannel.show(true);
            outputChannel.appendLine(`--- SECURITY AUDIT (${new Date().toLocaleString()}, registry: ${editorRegistry || 'unfiltered'}) ---`);
            if (skipped > 0) outputChannel.appendLine(`(skipped ${skipped} allowlisted or already-uninstalled match(es))`);
            for (const { extension, advisory } of found) {
                const ver = (extension.packageJSON && extension.packageJSON.version) || 'unknown';
                const takedown = advisory.windowState === 'REMOVED' && advisory.takenDownAt ? ` (removed from registry ${advisory.takenDownAt})` : '';
                outputChannel.appendLine(`- ${extension.id}@${ver} [${advisory.severity || 'high'}]${takedown}: ${advisory.title || 'Malicious advisory'}`);
            }
        }

        const result = await handleAuditFindings({
            context, vscodeApi: vscode, findings: found, trigger, removalMode, telemetry,
            onRemoved: (items, action) => {
                // Mark as pending reload first, so the pane refresh triggered by
                // recordRemoved below already sees the amber state.
                for (const item of items) removedThisSession.add(String(item.extension.id || '').toLowerCase());
                history?.recordRemoved(items, action);
                for (const item of items) {
                    audit?.record({
                        type: 'removed',
                        id: item.extension.id,
                        version: (item.extension.packageJSON && item.extension.packageJSON.version) || 'unknown',
                        detail: action === 'auto' ? 'auto' : 'on request'
                    });
                }
            }
        });

        // Record this run for the dashboard. Hashes let the user verify later
        // exactly which extensions and which advisory set were compared.
        if (history) {
            const inventory = hashExtensions(allExtensions, provenanceMap);
            history.recordRun({
                at: startedAt,
                trigger,
                registry: editorRegistry,
                installed: inventory.length,
                findings: found.length,
                removed: result.removed || 0,
                advisoryCount: entries.length,
                advisoryHash: hashAdvisorySet(entries),
                inventoryHash: hashInventory(inventory),
                source,
                stale: Boolean(stale)
            }, inventory);
        }
        // `flaggedIds` lets the post-install scan write "clear" or "flagged"
        // into the audit log for the extension that was just installed.
        // `startedAt` timestamps that entry before any removal this cycle made.
        return { ...pkgscan.state, startedAt, flaggedIds: found.map(f => String(f.extension.id || '').toLowerCase()) };
    } catch (error) {
        console.error('Error during security audit:', error);
        telemetry?.record('audit_error', { trigger, kind: 'audit_failed' });
        notifyAuditError(context, vscode, trigger);
        return { failureCount: 1, minWaitMs: 0 };
    } finally {
        void telemetry?.flush();
    }
}

function deactivate() {
    const proxyCtrl = activeProxyController;
    const tel = activeTelemetry;
    activeProxyController = null;
    activeTelemetry = null;
    try { proxyCtrl?.deactivate(); } catch (_e) { /* ignore */ }
    try { tel?.dispose(); } catch (_e) { /* ignore */ }
}

module.exports = {
    activate,
    deactivate,
    findMatchingAdvisories,
    classifySource,
    checkAndReportMaliciousExtensions
};
