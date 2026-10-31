/**
 * Extension Security Auditor for VS Code-compatible IDEs
 *
 * @fileoverview Scans and monitors installed extensions against the pkgscan.dev
 *               advisories feed and community blocklist.
 *
 * @description Runs on the VS Code extension API (VS Code, Cursor, Windsurf,
 *             VSCodium, and other forks):
 *             - Polls pkgscan.dev every 5 minutes (with jitter, ETag, and backoff)
 *             - Keeps a persistent sync pointer so advisories posted while the
 *               editor was closed are never missed
 *             - Filters advisories by the active editor's marketplace registry
 *               (while checking sideloaded VSIX extensions against all registries)
 *             - Supports `auto` (default), `prompt`, and `warn` removal modes
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
    fetchPageWithMeta,
    mergeAdvisories,
    fetchPkgscanAdvisories
} = require('./advisories/sync');
const { createAdvisoryMonitor } = require('./monitor');
const { createHistoryStore, hashExtensions, hashAdvisorySet, hashInventory } = require('./history');
const { createPane } = require('./ui/pane');
const { readAllowlist, filterLiveFindings } = require('./allowlist');
const { createAuditLog, scanAfterInstall } = require('./audit');
const {
    severityRank,
    showAutoModeDisclosureOnce,
    notifyAuditError,
    handleAuditFindings
} = require('./notifier');

// Community-maintained blocklist used as the base for every audit.
const GITHUB_BLOCKLIST_URL = 'https://raw.githubusercontent.com/yeeth-security/dev-guard/refs/heads/main/malicious.json';
const GITHUB_BLOCKLIST_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const RECENT_SYNC_REUSE_MS = 4 * 60 * 1000; // Reuse cache on change events within 4 min of a poll

function getRemovalMode() {
    try {
        const raw = vscode.workspace.getConfiguration('devGuard').get('removalMode', 'auto');
        return raw === 'prompt' || raw === 'warn' ? raw : 'auto';
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
    const outputChannel = vscode.window.createOutputChannel('Extension Security Auditor');
    telemetry.showNoticeOnce();
    showAutoModeDisclosureOnce(context, vscode, getRemovalMode());
    telemetry.record('activated');

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

    // Background monitor: jittered startup check + 5-minute poll loop + focus/change listeners.
    const monitor = createAdvisoryMonitor({
        vscodeApi: vscode,
        runAudit: trigger => checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger, history, audit)
    });
    monitor.start();

    // When an extension is installed or updated, scan right away (no debounce)
    // and write the outcome for that extension into the audit log.
    const auditWatcher = vscode.extensions.onDidChange(() => {
        const events = audit.syncInstalled(vscode.extensions.all);
        const added = events.filter(e => e.type === 'installed' || e.type === 'updated');
        if (added.length > 0) void scanAfterInstall(monitor, audit, added);
    });

    // Side pane in the Activity Bar (shield icon). "DevGuard: Show Panel" focuses it.
    const pane = createPane({
        history,
        audit,
        telemetry,
        getStatus: () => getPaneStatus(context),
        runScan: () => {
            telemetry.record('manual_scan_triggered', { from: 'panel' });
            return monitor.executeCycle('manual');
        }
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
        vscode.commands.registerCommand('devGuard.showPanel', () => pane.show())
    );

    context.subscriptions.push(monitor, outputChannel, pane, auditWatcher, ...commandDisposables);
    context.subscriptions.push({ dispose: () => { void telemetry.flush(); } });
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
function resolveRegistry() {
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

function getPaneStatus(context) {
    const { registry, method, detected, marketplaceMode, marketplaceUrl } = resolveRegistry();
    const state = loadSyncState(context);
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
        pointer: state.pointer || null
    };
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

function loadBundledBlocklistIds(context) {
    const maliciousFilePath = path.join(context.extensionPath, 'malicious.json');
    if (!fs.existsSync(maliciousFilePath)) return [];
    try {
        const parsed = JSON.parse(fs.readFileSync(maliciousFilePath, 'utf8'));
        return Array.isArray(parsed) ? parsed.filter(id => typeof id === 'string' && id.includes('.')) : [];
    } catch (_error) {
        return [];
    }
}

function blocklistToEntries(ids, title) {
    return ids.map(id => ({
        id: `blocklist:${id.toLowerCase()}`,
        extensionId: id,
        version: '*',
        registry: null,
        platform: 'universal',
        severity: 'high',
        title,
        summary: null,
        permalink: null,
        updatedAt: null
    }));
}

async function getGithubBlocklist(context) {
    const cacheFilePath = getStoragePath(context, 'github-blocklist-cache.json');
    const cache = readCache(cacheFilePath, 'ids');
    const now = Date.now();
    if (cache && (now - cache.timestamp) < GITHUB_BLOCKLIST_CACHE_TTL_MS) {
        return { ids: cache.ids, source: 'GitHub blocklist cache', stale: false };
    }
    try {
        const res = await fetchPageWithMeta(GITHUB_BLOCKLIST_URL);
        const ids = Array.isArray(res.data) ? res.data.filter(id => typeof id === 'string' && id.includes('.')) : [];
        if (ids.length === 0) throw new Error('GitHub blocklist is empty');
        writeCache(cacheFilePath, { timestamp: now, ids });
        return { ids, source: 'GitHub blocklist', stale: false };
    } catch (error) {
        console.warn('Failed to fetch GitHub blocklist:', error);
    }
    if (cache && cache.ids.length > 0) return { ids: cache.ids, source: 'GitHub blocklist cache (stale)', stale: true };
    const bundled = loadBundledBlocklistIds(context);
    return bundled.length > 0 ? { ids: bundled, source: 'bundled malicious.json', stale: true } : { ids: [], source: 'none', stale: true };
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
            return { entries: cache.entries, source: 'pkgscan.dev (304)', stale: false, state: nextState };
        }
        const entries = full ? result.entries : mergeAdvisories(cache ? cache.entries : [], result.entries);
        const nextState = recordSyncSuccess(state, { items: result.rawItems, full, etag: result.etag, minWaitMs: result.minWaitMs, now });
        writeCache(cacheFilePath, { timestamp: now, registry: registry || null, entries });
        saveSyncState(context, nextState);
        return { entries, source: 'pkgscan.dev', stale: false, state: nextState };
    } catch (error) {
        console.warn('Failed to fetch advisories from pkgscan.dev:', error);
        const failedState = recordSyncFailure(state);
        saveSyncState(context, failedState);
        telemetry?.record('poll_error', { trigger, kind: 'pkgscan_fetch_failed' });
        if (hasCached) return { entries: cache.entries, source: 'pkgscan.dev cache (stale)', stale: true, state: failedState };
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
    if (value.includes('pkgscan') && value.includes('GitHub')) return 'github+pkgscan';
    if (value.includes('pkgscan')) return 'pkgscan';
    if (value.includes('GitHub')) return 'github';
    if (value.includes('bundled')) return 'bundled';
    return 'none';
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
        const { registry: editorRegistry } = resolveRegistry();
        const provenanceMap = loadExtensionProvenance(allExtensions);
        const hasNonGallery = allExtensions.some(ext => {
            if (!ext || (ext.packageJSON && ext.packageJSON.isBuiltin)) return false;
            const prov = provenanceMap.get(String(ext.id || '').toLowerCase());
            return !prov || prov.source !== 'gallery';
        });
        const queryRegistry = editorRegistry && !hasNonGallery ? editorRegistry : null;

        const [github, pkgscan] = await Promise.all([
            getGithubBlocklist(context),
            getPkgscanAdvisories(context, { trigger, registry: queryRegistry, telemetry })
        ]);
        const entries = pkgscan.entries.concat(blocklistToEntries(github.ids, 'Listed on the known malicious extensions blocklist'));
        const sources = [github.source, pkgscan.source].filter(s => s && s !== 'none');
        const source = sources.length > 0 ? sources.join(' + ') : 'none';
        const stale = github.stale || pkgscan.stale;

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
        telemetry?.record('audit_completed', { trigger, duration, installed: bucketCount(allExtensions.length), findings: found.length, source: classifySource(source), stale: Boolean(stale) });
        telemetry?.record('poll_completed', { trigger, duration, findings: found.length, mode: removalMode, stale: Boolean(stale) });

        for (const { extension, advisory } of found) {
            telemetry?.record('malicious_found', {
                extension_id: extension.id,
                severity: advisory.severity || 'unknown',
                source: advisory.permalink ? 'pkgscan' : 'github',
                installed_version: (extension.packageJSON && extension.packageJSON.version) || 'unknown'
            });
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

function deactivate() {}

module.exports = {
    activate,
    deactivate,
    findMatchingAdvisories,
    classifySource
};
