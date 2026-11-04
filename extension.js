/**
 * Extension Security Auditor for VS Code-compatible IDEs
 *
 * @fileoverview Scans and monitors installed extensions against the pkgscan.dev
 *               advisories feed. Packages the feed does not list are still
 *               checked with the pkgscan engine scan after an allowlist revoke.
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
const { describeThreats } = require('./threats');
const { createPane, inspectSetting } = require('./ui/pane');
const { notifyUnmetHealthChecks } = require('./hardening');
const { readAllowlist, filterLiveFindings, diffIdSets, isStillOnDisk } = require('./allowlist');
const { createAuditLog, createSettledInstalledSync, scanAfterInstall, revokedExtensionIds } = require('./audit');
const {
    severityRank,
    showAutoModeDisclosureOnce,
    notifyAuditError,
    handleAuditFindings,
    handleFileFindings,
    remindPendingReload,
    uninstallFindings,
    openRemovalGuide,
    GUIDE_BUTTON,
    forgetExtensionsInLedger,
    forgetFileHashesInLedger
} = require('./notifier');
const { createScanFetcher, collectEngineThreats } = require('./proxy/readme');
const { createProxyController } = require('./proxy');
const { isLoopbackUrl, loadProxyState } = require('./proxy/config');
const {
    runLocalFileScan,
    createWorkspaceWatchers,
    readAllowedFiles,
    formatAllowedFileEntry,
    allowFileHash,
    unallowFileHash,
    listQuarantined,
    quarantineFinding,
    restoreQuarantinedFile,
    inspectFinding,
    terminateMaliciousTasks,
    disableAutoTasksIfThreatFound,
    createTaskInterceptor
} = require('./scanner');

// The pkgscan.dev advisories feed is the only advisory source. See ENG-25.
// The community blocklist file malicious.json stays at its public URL for
// clients published before 0.1.1. This version does not read it.
const RECENT_SYNC_REUSE_MS = 4 * 60 * 1000; // Reuse cache on change events within 4 min of a poll
let latestAdvisories = null;
let latestFileThreats = [];
// Flagged extensions still installed. The Extension threats section reads this.
let latestExtensionFindings = [];
// Ids the user just revoked. The next audit asks pkgscan's engine scan about
// them, because some blocked packages are not in the advisory feed.
const revokedAwaitingEngineScan = new Set();
// Engine-scan advisories kept until the extension is allowlisted or gone.
const rememberedEngineThreats = new Map();
// Completed engine scans that were not a block. Avoids asking pkgscan again
// on every poll. A new revoke deletes the id so it is checked once more.
const engineScanCleared = new Set();
// Longer than the README lookup. A revoke scan should wait for the verdict
// instead of timing out and telling the user everything is fine.
const engineScanFetcher = createScanFetcher({ timeoutMs: 8000 });

/** Remember revoked ids so the following scan can flag them again. */
function noteAllowlistRevoked(ids) {
    for (const id of ids || []) {
        const key = String(id || '').toLowerCase();
        if (!key) continue;
        revokedAwaitingEngineScan.add(key);
        engineScanCleared.delete(key);
    }
}

/**
 * Adds engine-scan threats for extensions that just left the allowlist.
 * Advisory matches already in `found` are left alone. A remembered threat
 * stays until the extension is allowlisted again or is no longer installed.
 */
async function appendRevokedEngineThreats(found, allExtensions, allowlist, editorRegistry, audit) {
    for (const id of [...rememberedEngineThreats.keys()]) {
        if (allowlist.has(id)) rememberedEngineThreats.delete(id);
    }
    const installed = new Set((allExtensions || []).filter(ext => ext && ext.id).map(ext => String(ext.id).toLowerCase()));
    const pending = new Set(revokedAwaitingEngineScan);
    revokedAwaitingEngineScan.clear();
    const events = audit && typeof audit.list === 'function' ? audit.list() : [];
    for (const id of revokedExtensionIds(events, allowlist)) {
        if (!installed.has(id) || rememberedEngineThreats.has(id) || engineScanCleared.has(id)) continue;
        pending.add(id);
    }
    const skipIds = new Set(found.map(item => String(item.extension && item.extension.id || '').toLowerCase()));
    const { threats, retry, checked } = await collectEngineThreats({
        ids: [...pending],
        extensions: allExtensions,
        allowlist,
        skipIds,
        registry: editorRegistry,
        getScanData: engineScanFetcher.getScanData
    });
    for (const id of retry) revokedAwaitingEngineScan.add(id);
    const fresh = [];
    for (const item of threats) {
        const id = String(item.extension.id).toLowerCase();
        // First time we learn about this engine flag. The caller drops the old
        // ledger row so this scan still shows a warning.
        if (!rememberedEngineThreats.has(id)) fresh.push(id);
        rememberedEngineThreats.set(id, item.advisory);
    }
    for (const id of checked || []) {
        if (!rememberedEngineThreats.has(id)) engineScanCleared.add(id);
    }
    for (const [id, advisory] of rememberedEngineThreats) {
        if (skipIds.has(id) || allowlist.has(id)) continue;
        const ext = (allExtensions || []).find(item => item && String(item.id).toLowerCase() === id);
        if (!ext || !isStillOnDisk(ext)) {
            rememberedEngineThreats.delete(id);
            continue;
        }
        found.push({ extension: ext, advisory });
        skipIds.add(id);
    }
    return fresh;
}
let activeProxyController = null;
let activeTelemetry = null;
let activeMonitor = null;
let activeWorkspaceWatchers = null;

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
    // The extension list is compared after it settles, not on the first
    // onDidChange. A reload reports extensions missing and then back.
    const audit = createAuditLog(context, { getLimit: getHistoryLimit });

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
        if (
            e.affectsConfiguration('devGuard.proxy.enabled') ||
            e.affectsConfiguration('extensions.gallery.serviceUrl')
        ) {
            void proxyController.sync();
        }
    });

    // Background monitor: jittered startup check + 5-minute poll loop + focus/change listeners.
    const monitor = createAdvisoryMonitor({
        vscodeApi: vscode,
        runAudit: trigger => checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger, history, audit, {
            onRefresh: () => pane?.refresh(),
            onOpenPane: () => pane?.show()
        })
    });
    activeMonitor = monitor;
    monitor.start();

    // One wait for startup and for every later list change. Each onDidChange
    // resets it. When it fires, the list has stopped flickering, so a reload
    // does not log Uninstalled and then Installed for the same version.
    // A real install is recorded once, then scanned. checkSelfUninstall stays
    // immediate: that one must not wait a second.
    const settledInstallSync = createSettledInstalledSync({
        sync: () => audit.syncInstalled(vscode.extensions.all),
        onSettled: events => {
            const added = (events || []).filter(e => e.type === 'installed' || e.type === 'updated');
            if (added.length > 0) void scanAfterInstall(monitor, audit, added);
        }
    });
    settledInstallSync.scheduleSync();
    const auditWatcher = vscode.extensions.onDidChange(() => {
        void proxyController.checkSelfUninstall();
        settledInstallSync.scheduleSync();
    });

    // Side pane in the Activity Bar (shield icon). "DevGuard: Show Panel" focuses it.
    const runFileThreatScan = (trigger = 'startup', recordRun = true) =>
        scanAndHandleFileThreats({
            context, telemetry, outputChannel, history, audit,
            onRefresh: () => pane?.refresh(),
            onOpenPane: () => pane?.show(),
            trigger, recordRun
        });

    pane = createPane({
        history,
        audit,
        telemetry,
        getStatus: () => getPaneStatus(context, proxyController),
        getFileThreats: () => latestFileThreats,
        getQuarantined: () => listQuarantined(context),
        onQuarantineFile: async filePath => {
            const target = latestFileThreats.find(f => f.filePath === filePath);
            if (!target) return;
            const res = quarantineFinding(context, target);
            if (res.ok) {
                const rules = [...new Set((target.matches || []).map(m => m.rule))].join(', ');
                audit.record({
                    type: 'quarantined',
                    id: target.displayPath || target.fileName,
                    filePath: target.filePath,
                    quarantinedPath: res.quarantinedPath,
                    sha256: target.sha256,
                    detail: `${target.severity}${rules ? ` · ${rules}` : ''}`
                });
                telemetry.record('file_threat_action', { action: 'quarantine', count: 1, from: 'pane' });
                await runFileThreatScan('change', true);
            }
        },
        onRestoreFile: async key => {
            const res = restoreQuarantinedFile(context, key);
            if (res.ok && res.record) {
                const rec = res.record;
                reportedFileAuditKeys.delete(`${rec.filePath}::${rec.sha256 || ''}`);
                audit.record({
                    type: 'restored',
                    id: rec.displayPath || rec.fileName,
                    detail: 'from quarantine'
                });
                telemetry.record('file_threat_action', { action: 'restore', count: 1, from: 'pane' });
                await runFileThreatScan('change', true);
            }
        },
        onInspectFile: async filePath => {
            const target = latestFileThreats.find(f => f.filePath === filePath) || { filePath };
            telemetry.record('file_threat_action', { action: 'inspect', count: 1, from: 'pane' });
            await inspectFinding(vscode, target);
        },
        getExtensionThreats: () => currentExtensionThreats(),
        onRemoveExtension: async id => {
            const key = String(id || '').toLowerCase();
            const item = latestExtensionFindings.find(f => String(f.extension && f.extension.id || '').toLowerCase() === key);
            if (!item) return;
            const { removed } = await uninstallFindings(vscode, [item], telemetry, 'uninstall_clicked');
            if (removed.length === 0) return;
            noteExtensionRemoved(history, audit, removed, 'manual');
            void vscode.window.showInformationMessage(
                'Security audit completed. Reload the window to finish uninstalling extensions.',
                'Reload Window', GUIDE_BUTTON
            ).then(choice => {
                if (choice === 'Reload Window') {
                    telemetry.record('reload_clicked', { from: 'pane_uninstall' });
                    void vscode.commands.executeCommand('workbench.action.reloadWindow');
                } else if (choice === GUIDE_BUTTON) {
                    openRemovalGuide(vscode, telemetry, 'pane_uninstall');
                }
            });
        },
        onAllowFile: async sha256 => {
            const target = latestFileThreats.find(f => f.sha256 === sha256);
            const name = (target && (target.displayPath || target.fileName)) || '';
            await allowFileHash(vscode, sha256, name);
            audit.record({
                type: 'file_allowed',
                id: formatAllowedFileEntry(name, sha256) || sha256.slice(0, 12),
                sha256
            });
            telemetry.record('file_threat_action', { action: 'allow', count: 1, from: 'pane' });
            await runFileThreatScan('change', true);
        },
        onUnallowFile: async (sha256, label) => {
            await unallowFileHash(vscode, sha256);
            for (const k of [...reportedFileAuditKeys]) {
                if (k.toLowerCase().endsWith(`::${sha256.toLowerCase()}`)) reportedFileAuditKeys.delete(k);
            }
            audit.record({
                type: 'file_unallowed',
                id: label || sha256.slice(0, 12),
                sha256,
                detail: `⌗${sha256.slice(0, 8)}`
            });
            telemetry.record('file_threat_action', { action: 'unallow', count: 1, from: 'pane' });
            await runFileThreatScan('change', true);
        },
        setProxy: enabled => proxyController.setEnabled(enabled, 'panel'),
        setUpstreamMarketplace: value => proxyController.setUpstreamMarketplace(value),
        runScan: async () => {
            telemetry.record('manual_scan_triggered', { from: 'panel' });
            await runFileThreatScan('manual', false);
            return monitor.executeCycle('manual');
        }
    });

    // Run local profile (~/.vscode) and workspace (.vscode/, .git/hooks) scan immediately at 0ms
    // so auto-run tasks and staged payloads are caught without waiting for network poll jitter.
    const initialFileScan = runFileThreatScan('startup', true);
    const taskInterceptor = createTaskInterceptor({
        vscodeApi: vscode,
        getFindings: () => latestFileThreats,
        onTerminated: () => pane?.refresh(),
        audit,
        telemetry
    });
    const workspaceWatchers = createWorkspaceWatchers({
        vscodeApi: vscode,
        onTrigger: () => { void runFileThreatScan('change', true); }
    });
    activeWorkspaceWatchers = workspaceWatchers;

    // Warn the user on startup if any editor health check items (or the proxy) are not met,
    // and record the user's deduplicated editor security posture once proxy sync finishes.
    void Promise.allSettled([initialProxySync, initialFileScan]).finally(() => {
        const proxyStatus = proxyController.getStatus();
        notifyUnmetHealthChecks({
            inspectFn: inspectSetting,
            appName: vscode.env && vscode.env.appName,
            editorVersion: vscode.version,
            proxyEnabled: proxyStatus.proxyEnabled,
            proxyNeedsRestart: proxyStatus.proxyNeedsRestart,
            fileThreatCount: latestFileThreats.length,
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
        void runFileThreatScan('manual', false);
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
        vscode.commands.registerCommand('devGuard.scanWorkspace', () => {
            telemetry.record('manual_scan_triggered', { from: 'workspace_command' });
            void runFileThreatScan('manual', true);
        }),
        vscode.commands.registerCommand('devGuard.showPanel', () => pane.show()),
        vscode.commands.registerCommand('devGuard.toggleProxy', () => {
            const next = !proxyController.getStatus().proxyEnabled;
            void proxyController.setEnabled(next, 'command');
        })
    );

    // Settings edits do not go through the pane's Allow / Revoke buttons.
    // When an id leaves the allowlist we forget its notification history and
    // scan again, so the next check actually flags it.
    const allowlistWatcher = watchAllowlistSettings({
        context,
        vscodeApi: vscode,
        audit,
        telemetry,
        monitor,
        rescanFiles: () => runFileThreatScan('change', true)
    });

    context.subscriptions.push(
        monitor, outputChannel, pane, proxyController, proxyConfigWatcher,
        allowlistWatcher, auditWatcher, taskInterceptor, workspaceWatchers, ...commandDisposables
    );
    context.subscriptions.push({ dispose: () => { telemetry.dispose(); settledInstallSync.dispose(); } });
}

const reportedFileAuditKeys = new Set();

/**
 * Records a standalone file-scan entry into the Scan log (`history`).
 * `fileThreats` is the list of findings (not just a count) so the Scan log
 * can show WHAT was found.
 */
function recordFileScanRun(context, history, trigger, fileThreats) {
    if (!history) return;
    const allExtensions = (vscode.extensions && vscode.extensions.all) || [];
    const provenanceMap = loadExtensionProvenance(allExtensions);
    const inventory = hashExtensions(allExtensions, provenanceMap);
    const entries = getCachedAdvisories(context);
    const { registry: editorRegistry } = resolveRegistry(context);
    history.recordRun({
        at: Date.now(),
        trigger,
        registry: editorRegistry,
        installed: inventory.length,
        findings: 0,
        fileFindings: fileThreats.length,
        details: describeThreats({ fileThreats }),
        removed: 0,
        advisoryCount: entries.length,
        advisoryHash: hashAdvisorySet(entries),
        inventoryHash: hashInventory(inventory),
        source: 'local',
        stale: false
    }, inventory);
}

/**
 * Scans user-profile (`~/.vscode`) and workspace (`.vscode/`, `.git/hooks`, `.npmrc`)
 * files, logs findings to the Audit log and Scan log, terminates running malicious tasks,
 * and alerts the user.
 */
async function scanAndHandleFileThreats({ context, telemetry, outputChannel, history, audit, onRefresh, onOpenPane, trigger = 'startup', recordRun = false }) {
    try {
        const previousCount = latestFileThreats.length;
        const findings = runLocalFileScan({ vscodeApi: vscode });
        latestFileThreats = findings;
        terminateMaliciousTasks({ vscodeApi: vscode, findings, audit, telemetry });
        await disableAutoTasksIfThreatFound({ vscodeApi: vscode, findings, audit, telemetry });

        // Log newly detected file threats into the Audit log (deduplicated per file+sha256).
        for (const f of findings) {
            const auditKey = `${f.filePath}::${f.sha256 || ''}`;
            const subj = f.displayPath || f.fileName;
            const lastEvt = audit && typeof audit.lastEventFor === 'function' ? audit.lastEventFor(subj) : null;
            if (!reportedFileAuditKeys.has(auditKey) && (!lastEvt || lastEvt.type !== 'file_threat')) {
                reportedFileAuditKeys.add(auditKey);
                const rules = [...new Set((f.matches || []).map(m => m.rule))].join(', ');
                audit?.record({
                    type: 'file_threat',
                    id: subj,
                    detail: `${f.severity}${rules ? ` · ${rules}` : ''}`
                });
            }
        }

        // Record in Scan log when triggered standalone and threats are found, cleared, or manually checked.
        if (recordRun && (findings.length > 0 || previousCount !== findings.length || trigger === 'manual')) {
            recordFileScanRun(context, history, trigger, findings);
        }

        onRefresh?.();

        if (findings.length > 0 && outputChannel) {
            outputChannel.appendLine(`--- FILE THREAT SCAN (${new Date().toLocaleString()}) ---`);
            for (const f of findings) {
                const rules = (f.matches || []).map(m => `${m.rule}(${m.technique})`).join(', ');
                outputChannel.appendLine(`- ${f.displayPath} [${f.severity}]: ${rules}`);
            }
        }

        await handleFileFindings({
            context,
            vscodeApi: vscode,
            findings,
            trigger,
            telemetry,
            onQuarantine: async items => {
                for (const item of items) {
                    const res = quarantineFinding(context, item);
                    if (res.ok) {
                        const rules = [...new Set((item.matches || []).map(m => m.rule))].join(', ');
                        audit?.record({
                            type: 'quarantined',
                            id: item.displayPath || item.fileName,
                            filePath: item.filePath,
                            quarantinedPath: res.quarantinedPath,
                            sha256: item.sha256,
                            detail: `${item.severity}${rules ? ` · ${rules}` : ''}`
                        });
                    }
                }
                latestFileThreats = runLocalFileScan({ vscodeApi: vscode });
                recordFileScanRun(context, history, 'change', latestFileThreats);
                onRefresh?.();
            },
            onInspect: async item => {
                await inspectFinding(vscode, item);
            },
            onOpenPane: () => onOpenPane?.()
        });
        return findings;
    } catch (error) {
        console.warn('Error during file threat scan:', error);
        return [];
    }
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
// The last auto-removal, so a later scan can show the reload toast again
// after the extension has already dropped off the installed list.
let pendingReloadNotice = null;

/**
 * Records an uninstall in the session set, the removed history, and the audit log.
 * The pane refresh that follows drops the extension from Extension threats.
 */
function noteExtensionRemoved(history, audit, items, action) {
    for (const item of items) removedThisSession.add(String(item.extension.id || '').toLowerCase());
    if (action === 'auto' && items.length > 0) {
        const first = items[0];
        pendingReloadNotice = {
            names: items.map(f => `'${(f.extension.packageJSON && f.extension.packageJSON.displayName) || f.extension.id}'`).join(', '),
            reportUrl: (items.find(f => f.advisory && f.advisory.permalink) || {}).advisory?.permalink || null,
            extensionId: first.extension.id,
            severity: (first.advisory && first.advisory.severity) || 'unknown'
        };
    }
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

/** Plain rows for the Extension threats section. Allowlisted and already-removed ids are left out. */
function currentExtensionThreats() {
    const allow = readAllowlist(vscode);
    return latestExtensionFindings.filter(item => {
        const id = String(item.extension && item.extension.id || '').toLowerCase();
        return id && !removedThisSession.has(id) && !allow.has(id);
    }).map(item => {
        const pkg = (item.extension && item.extension.packageJSON) || {};
        const advisory = item.advisory || {};
        return {
            id: item.extension.id,
            version: pkg.version || 'unknown',
            severity: advisory.severity || 'high',
            title: advisory.title || '',
            permalink: advisory.permalink || ''
        };
    });
}

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

/** Drops this session's `malicious_found` keys so a re-flag is reported again. */
function forgetReportedFindings(extensionId) {
    const prefix = `${String(extensionId || '').toLowerCase()}@`;
    for (const key of reportedFindings) {
        if (key.startsWith(prefix)) reportedFindings.delete(key);
    }
}

/** Drops file-audit dedupe keys for a SHA-256 that just left the file allowlist. */
function forgetReportedFileKeys(sha256) {
    const suffix = `::${String(sha256 || '').toLowerCase()}`;
    for (const key of reportedFileAuditKeys) {
        if (key.toLowerCase().endsWith(suffix)) reportedFileAuditKeys.delete(key);
    }
}

/**
 * True when the pane or the block modal just wrote this audit event.
 * Those paths record after the settings write, so we wait a tick and then
 * skip, instead of logging the same allowlist edit twice.
 */
function justRecorded(audit, id, type) {
    const last = audit && typeof audit.lastEventFor === 'function' ? audit.lastEventFor(id) : null;
    return Boolean(last && last.type === type && Date.now() - (last.at || 0) < 2000);
}

/**
 * Reacts to `devGuard.allowlist` and `devGuard.allowedFiles` changing in the
 * Settings UI (or anywhere else). Removing an entry must update the ledger,
 * the audit log, and kick a scan. Adding an entry only needs the audit log;
 * the next scan already reads the list fresh.
 */
function watchAllowlistSettings({ context, vscodeApi, audit, telemetry, monitor, rescanFiles }) {
    let knownAllowlist = readAllowlist(vscodeApi);
    let knownFiles = readAllowedFiles(vscodeApi);

    return vscodeApi.workspace.onDidChangeConfiguration(event => {
        const allowlistChanged = event.affectsConfiguration('devGuard.allowlist');
        const filesChanged = event.affectsConfiguration('devGuard.allowedFiles');
        if (!allowlistChanged && !filesChanged) return;

        if (allowlistChanged) {
            const next = readAllowlist(vscodeApi);
            const { removed, added } = diffIdSets(knownAllowlist, next);
            knownAllowlist = next;
            // Forget first, then scan, so this cycle is not swallowed by the ledger.
            if (removed.length > 0) {
                // 'unallow' always notifies. A plain 'change' scan would stay
                // quiet when the ledger still remembers the earlier warning.
                forgetExtensionsInLedger(context, removed);
                for (const id of removed) forgetReportedFindings(id);
                noteAllowlistRevoked(removed);
                void monitor.executeCycle('unallow');
            }
            // The pane and the block modal write their own audit row after the
            // setting update. Wait a tick so we do not log the same edit twice.
            if (removed.length > 0 || added.length > 0) {
                setTimeout(() => {
                    for (const id of removed) {
                        if (justRecorded(audit, id, 'unallowed')) continue;
                        audit?.record({ type: 'unallowed', id, detail: 'settings' });
                        telemetry?.record('allowlist_removed', { extension_id: id, from: 'settings' });
                    }
                    for (const id of added) {
                        if (justRecorded(audit, id, 'allowed')) continue;
                        audit?.record({ type: 'allowed', id, detail: 'settings' });
                        telemetry?.record('allowlist_added', { extension_id: id, from: 'settings' });
                    }
                }, 0);
            }
        }

        if (filesChanged) {
            const nextFiles = readAllowedFiles(vscodeApi);
            const { removed } = diffIdSets(knownFiles, nextFiles);
            knownFiles = nextFiles;
            if (removed.length === 0) return;
            forgetFileHashesInLedger(context, removed);
            for (const hash of removed) forgetReportedFileKeys(hash);
            void rescanFiles?.();
        }
    });
}

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
async function checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger = 'startup', history = null, audit = null, hooks = {}) {
    const allExtensions = vscode.extensions.all || [];
    const startedAt = Date.now();
    const removalMode = getRemovalMode();

    await scanAndHandleFileThreats({
        context, telemetry, outputChannel, history, audit, trigger, recordRun: false,
        onRefresh: hooks.onRefresh,
        onOpenPane: hooks.onOpenPane
    });

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

        // Drop allowlisted extensions and ones already uninstalled (waiting for
        // reload). What is left is a real, live threat — including reinstalls,
        // which auto mode removes again every time.
        // Revoked ids that the advisory feed does not list are checked against
        // the pkgscan engine scan, so a package like Ackee is flagged again.
        const allow = readAllowlist(vscode);
        const matched = entries.length > 0
            ? findMatchingAdvisories(allExtensions, entries, provenanceMap, editorRegistry)
            : [];
        const found = filterLiveFindings(matched, allow);
        const freshEngineFlags = await appendRevokedEngineThreats(found, allExtensions, allow, editorRegistry, audit);
        if (freshEngineFlags.length > 0) {
            forgetExtensionsInLedger(context, freshEngineFlags);
            for (const id of freshEngineFlags) forgetReportedFindings(id);
        }
        if (entries.length === 0 && found.length === 0) {
            telemetry?.record('audit_error', { trigger, kind: 'no_advisory_data' });
            // The removed extension is no longer in the feed match, but the
            // reload still has not happened. Show that toast again.
            if (removalMode === 'auto' && pendingReloadNotice) {
                remindPendingReload(vscode, telemetry, pendingReloadNotice);
            }
            return pkgscan.state;
        }
        const skipped = matched.length - found.length;
        const duration = bucketDuration(Date.now() - startedAt);
        const installedBucket = bucketCount(allExtensions.length);
        const auditProps = { trigger, duration, installed: installedBucket, findings: found.length, source: classifySource(source), stale: Boolean(stale) };
        const pollProps = { trigger, duration, findings: found.length, mode: removalMode, stale: Boolean(stale) };

        // Avoid blasting identical clean poll events every 5 minutes (288x/day per open window).
        // Always record immediately when findings exist, when the feed is stale, or on manual/install checks;
        // for clean background/startup polls, record at most once per 24h heartbeat.
        if (found.length > 0 || stale || trigger === 'manual' || trigger === 'install' || trigger === 'unallow') {
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

        if (found.length > 0 || trigger === 'manual' || trigger === 'unallow') {
            if (trigger === 'manual') outputChannel.show(true);
            outputChannel.appendLine(`--- SECURITY AUDIT (${new Date().toLocaleString()}, registry: ${editorRegistry || 'unfiltered'}) ---`);
            if (skipped > 0) outputChannel.appendLine(`(skipped ${skipped} allowlisted or already-uninstalled match(es))`);
            for (const { extension, advisory } of found) {
                const ver = (extension.packageJSON && extension.packageJSON.version) || 'unknown';
                const takedown = advisory.windowState === 'REMOVED' && advisory.takenDownAt ? ` (removed from registry ${advisory.takenDownAt})` : '';
                outputChannel.appendLine(`- ${extension.id}@${ver} [${advisory.severity || 'high'}]${takedown}: ${advisory.title || 'Malicious advisory'}`);
            }
        }

        // A manual scan must not say "looking good" while an engine lookup
        // failed or is still unfinished. The next scan asks again.
        const notifyTrigger = found.length === 0 && revokedAwaitingEngineScan.size > 0 && trigger === 'manual'
            ? 'poll'
            : trigger;
        const result = await handleAuditFindings({
            context, vscodeApi: vscode, findings: found, trigger: notifyTrigger, removalMode, telemetry,
            pendingReload: removedThisSession.size > 0,
            onRemoved: (items, action) => {
                // Mark as pending reload first, so the pane refresh triggered by
                // recordRemoved below already sees the amber state.
                noteExtensionRemoved(history, audit, items, action);
            }
        });
        if (removalMode === 'auto' && pendingReloadNotice) {
            remindPendingReload(vscode, telemetry, pendingReloadNotice);
        }

        // Still-installed findings stay actionable in Extension threats.
        // Auto-removed ones were just added to removedThisSession, so they drop off.
        latestExtensionFindings = found.filter(item => {
            const id = String(item.extension && item.extension.id || '').toLowerCase();
            return id && !removedThisSession.has(id);
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
                fileFindings: latestFileThreats.length,
                // What was found, so the Scan log can name it (not just count it).
                details: describeThreats({ found, fileThreats: latestFileThreats, removedIds: removedThisSession }),
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
    const mon = activeMonitor;
    const watchers = activeWorkspaceWatchers;
    activeProxyController = null;
    activeTelemetry = null;
    activeMonitor = null;
    activeWorkspaceWatchers = null;
    try { watchers?.dispose(); } catch (_e) { /* ignore */ }
    try { mon?.dispose(); } catch (_e) { /* ignore */ }
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
