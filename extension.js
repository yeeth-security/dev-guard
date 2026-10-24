/**
 * Extension Security Auditor for Cursor
 * 
 * @fileoverview A security extension that scans and monitors installed extensions
 *              for known malicious patterns and provides real-time security alerts.
 * 
 * @author v0ldemort5545, unsafe_call
 * @version 0.0.1
 * @since 2025-08-19
 * 
 * @description This extension provides comprehensive security auditing for Cursor extensions:
 *             - Automatically scans all installed extensions on startup
 *             - Monitors for extension changes and re-runs security audits on extension changes
 *             - Provides uninstall options for malicious extensions
 * 
 * @usage The extension activates automatically on startup and can be manually triggered
 *        via the command palette: "Extension Security Auditor: Check Installed Extensions"
 * 
 */

// The module 'vscode' contains the Cursor extensibility API (Cursor is built on VS Code)
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

/**
 * This function is called when your extension is activated.
 * The 'activationEvents' in package.json determine when this runs.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Extension Security Auditor is now active in Cursor!');

    // Initial check on startup
    checkAndReportMaliciousExtensions(context).catch(error => {
        console.error('Error during initial security audit:', error);
        vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
    });

    // Subscribe to the onDidChange event
    context.subscriptions.push(vscode.extensions.onDidChange(() => {
        console.log('Extension list changed. Re-running security audit...');
        checkAndReportMaliciousExtensions(context).catch(error => {
            console.error('Error during security audit after extension change:', error);
            vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
        });
    }));

    let disposable = vscode.commands.registerCommand('extension-security-auditor.checkExtensions', () => {
        vscode.window.showInformationMessage('Starting security audit of installed extensions...');
        checkAndReportMaliciousExtensions(context).catch(error => {
            console.error('Error during manual security audit:', error);
            vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
        });
    });

    context.subscriptions.push(disposable);
}

/**
 * Public advisories API from pkgscan.dev.
 * @see https://www.pkgscan.dev/api/advisories?kind=malicious
 */
const PKGSCAN_ADVISORIES_URL = 'https://www.pkgscan.dev/api/advisories';
const PKGSCAN_PAGE_SIZE = 100;
const PKGSCAN_FETCH_TIMEOUT_MS = 15000;
const PKGSCAN_MAX_ATTEMPTS = 4;
const PKGSCAN_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const PKGSCAN_FULL_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Community-maintained blocklist used as the base for every audit.
 */
const GITHUB_BLOCKLIST_URL = 'https://raw.githubusercontent.com/janbro/openvsx-registry-guard/refs/heads/main/malicious.json';
const GITHUB_BLOCKLIST_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes (matches prior behavior)

/**
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Parses an ISO timestamp to milliseconds for reliable comparison.
 * @param {string|null|undefined} value
 * @returns {number} Milliseconds, or NaN when unparseable
 */
function timestampValue(value) {
    if (typeof value !== 'string') {
        return NaN;
    }
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? ms : NaN;
}

/**
 * Fetches a JSON document with a hard timeout and retries on rate limits.
 * @param {string} url
 * @param {number} [attempt]
 * @returns {Promise<any>}
 */
async function fetchJson(url, attempt = 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PKGSCAN_FETCH_TIMEOUT_MS);

    let response;
    try {
        response = await fetch(url, {
            headers: { accept: 'application/json' },
            signal: controller.signal
        });
    } finally {
        clearTimeout(timer);
    }

    if (response.status === 429 && attempt < PKGSCAN_MAX_ATTEMPTS) {
        const retryAfter = Number(response.headers && response.headers.get('retry-after'));
        const delay = Number.isFinite(retryAfter) && retryAfter > 0
            ? retryAfter * 1000
            : 1000 * Math.pow(2, attempt - 1);
        console.warn(`Rate limited by pkgscan.dev; retrying in ${delay}ms (attempt ${attempt}/${PKGSCAN_MAX_ATTEMPTS})`);
        await sleep(delay);
        return fetchJson(url, attempt + 1);
    }

    if (response.status >= 500 && attempt < PKGSCAN_MAX_ATTEMPTS) {
        const delay = 500 * attempt;
        console.warn(`pkgscan.dev returned ${response.status}; retrying in ${delay}ms`);
        await sleep(delay);
        return fetchJson(url, attempt + 1);
    }

    if (!response.ok) {
        throw new Error(`Request failed: ${response.status} ${response.statusText}`);
    }

    return await response.json();
}

/**
 * Normalizes one pkgscan advisory into the shape used by the auditor.
 * @param {any} item
 * @returns {{id: string|null, extensionId: string, version: string, severity: string|null, title: string|null, summary: string|null, permalink: string|null, updatedAt: string|null}|null}
 */
function toAdvisoryEntry(item) {
    if (!item || item.ecosystem !== 'vscode-extension') {
        return null;
    }

    const publisher = typeof item.namespace === 'string' ? item.namespace.trim() : '';
    const name = typeof item.name === 'string' ? item.name.trim() : '';
    if (!publisher || !name) {
        return null;
    }

    const permalink = typeof item.permalink === 'string' && item.permalink.startsWith('/')
        ? `https://www.pkgscan.dev${item.permalink}`
        : null;

    return {
        id: typeof item.id === 'string' ? item.id : null,
        extensionId: `${publisher}.${name}`,
        version: typeof item.version === 'string' && item.version ? item.version : '*',
        severity: item.severity || null,
        title: item.title || null,
        summary: item.summary || null,
        permalink,
        updatedAt: typeof item.updatedAt === 'string' ? item.updatedAt : null
    };
}

/**
 * Fetches every malicious advisory from pkgscan.dev.
 * The API caps `limit` at 100 and paginates with `offset`.
 * @returns {Promise<Array>} Advisory entries
 */
async function fetchPkgscanAdvisories({ cursor = null, full = true } = {}) {
    const pageUrl = offset => `${PKGSCAN_ADVISORIES_URL}?kind=malicious&limit=${PKGSCAN_PAGE_SIZE}&offset=${offset}`;
    const firstPage = await fetchJson(pageUrl(0));
    const firstItems = Array.isArray(firstPage.items) ? firstPage.items : [];
    const reportedTotal = Number(firstPage.total);
    const total = Number.isFinite(reportedTotal) && reportedTotal > 0 ? reportedTotal : firstItems.length;

    const entries = [];
    let newest = null;
    let reachedCursor = false;
    let scannedPages = 0;

    /**
     * Adds a page's items until the incremental cursor is reached.
     * Advisories are sorted newest-first by `updatedAt`.
     * @returns {boolean} false when the cursor has been reached
     */
    const collect = items => {
        for (const item of items) {
            if (!newest && item && typeof item.updatedAt === 'string') {
                newest = item.updatedAt;
            }

            // Incremental syncs stop as soon as they reach advisories that
            // were already present in the previous sync.
            if (!full && cursor && item && typeof item.updatedAt === 'string') {
                const updatedAt = timestampValue(item.updatedAt);
                const cursorAt = timestampValue(cursor);
                if (Number.isFinite(updatedAt) && Number.isFinite(cursorAt) && updatedAt < cursorAt) {
                    reachedCursor = true;
                    return false;
                }
            }

            const entry = toAdvisoryEntry(item);
            if (entry) {
                entries.push(entry);
            }
        }
        return true;
    };

    let done = !collect(firstItems);
    scannedPages++;

    // If a busy period added more than one page of advisories since the last
    // sync, keep paginating until the cursor is reached. A normal refresh
    // stops inside page 0.
    let offset = firstItems.length;
    while (!done && offset < total) {
        await sleep(100);

        let page;
        try {
            page = await fetchJson(pageUrl(offset));
        } catch (error) {
            console.warn(`Failed to fetch pkgscan advisories page at offset ${offset}:`, error);
            return { entries, complete: false, newest, reachedCursor, scannedPages };
        }

        const items = Array.isArray(page.items) ? page.items : [];
        if (items.length === 0) {
            break;
        }

        done = !collect(items);
        scannedPages++;
        offset += items.length;
    }

    console.log(
        `Fetched ${entries.length} malicious advisories from pkgscan.dev ` +
        `(${full ? 'full' : 'incremental'} sync, ${scannedPages} page${scannedPages === 1 ? '' : 's'})`
    );
    return { entries, complete: true, newest, reachedCursor, scannedPages };
}

const SEVERITY_RANK = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1
};

/**
 * @param {string|null} severity
 * @returns {number}
 */
function severityRank(severity) {
    return SEVERITY_RANK[(severity || '').toLowerCase()] || 0;
}

/**
 * Builds a case-insensitive advisory index keyed by extension ID.
 * @param {Array} entries
 * @returns {Map<string, {versions: Set<string>, severity: string|null, title: string|null, summary: string|null, permalink: string|null}>}
 */
function buildAdvisoryIndex(entries) {
    const index = new Map();

    for (const entry of entries) {
        const key = entry.extensionId.toLowerCase();
        let advisory = index.get(key);
        if (!advisory) {
            advisory = {
                versions: new Set(),
                severity: null,
                title: null,
                summary: null,
                permalink: null
            };
            index.set(key, advisory);
        }

        advisory.versions.add(entry.version || '*');

        if (severityRank(entry.severity) > severityRank(advisory.severity)) {
            advisory.severity = entry.severity;
        }
        if (!advisory.title && entry.title) {
            advisory.title = entry.title;
        }
        if (!advisory.summary && entry.summary) {
            advisory.summary = entry.summary;
        }
        if (!advisory.permalink && entry.permalink) {
            advisory.permalink = entry.permalink;
        }
    }

    return index;
}

/**
 * Returns the advisory that applies to an installed extension, if any.
 * Advisories with version "*" apply to every version; specific versions
 * must match the installed version.
 * @param {Map} index
 * @param {vscode.Extension<any>} extension
 */
function advisoryForExtension(index, extension) {
    const advisory = index.get(extension.id.toLowerCase());
    if (!advisory) {
        return null;
    }
    if (advisory.versions.has('*')) {
        return advisory;
    }

    const installedVersion = extension.packageJSON && extension.packageJSON.version;
    if (!installedVersion) {
        return advisory;
    }
    return advisory.versions.has(installedVersion) ? advisory : null;
}

/**
 * Loads the bundled malicious.json blocklist IDs as an offline fallback.
 * @param {vscode.ExtensionContext} context
 * @returns {string[]} Extension IDs
 */
function loadBundledBlocklistIds(context) {
    const maliciousFilePath = path.join(context.extensionPath, 'malicious.json');
    if (!fs.existsSync(maliciousFilePath)) {
        return [];
    }

    try {
        const parsed = JSON.parse(fs.readFileSync(maliciousFilePath, 'utf8'));
        if (!Array.isArray(parsed)) {
            return [];
        }
        const ids = parsed.filter(id => typeof id === 'string' && id.includes('.'));
        console.log(`Loaded ${ids.length} malicious extensions from bundled malicious.json`);
        return ids;
    } catch (error) {
        console.warn('Could not read bundled malicious.json:', error);
        return [];
    }
}

/**
 * Converts blocklist IDs into advisory entries.
 * @param {string[]} ids
 * @param {string} title
 * @returns {Array} Advisory entries
 */
function blocklistToEntries(ids, title) {
    return ids.map(id => ({
        id: `blocklist:${id.toLowerCase()}`,
        extensionId: id,
        version: '*',
        severity: 'high',
        title,
        summary: null,
        permalink: null,
        updatedAt: null
    }));
}

/**
 * @param {vscode.ExtensionContext} context
 * @param {string} fileName
 * @returns {string} Cache file path
 */
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

/**
 * @param {string} cacheFilePath
 * @param {string} field Required array field on the cached object
 * @returns {any|null}
 */
function readCache(cacheFilePath, field) {
    try {
        if (!fs.existsSync(cacheFilePath)) {
            return null;
        }
        const parsed = JSON.parse(fs.readFileSync(cacheFilePath, 'utf8'));
        if (!parsed || !Array.isArray(parsed[field])) {
            return null;
        }
        return parsed;
    } catch (error) {
        console.warn(`Could not read cache ${cacheFilePath}:`, error);
        return null;
    }
}

/**
 * @param {string} cacheFilePath
 * @param {any} value
 */
function writeCache(cacheFilePath, value) {
    try {
        fs.writeFileSync(cacheFilePath, JSON.stringify(value), 'utf8');
    } catch (error) {
        console.warn(`Could not write cache ${cacheFilePath}:`, error);
    }
}

/**
 * Fetches the community blocklist from GitHub.
 * @returns {Promise<string[]>} Extension IDs
 */
async function fetchGithubBlocklist() {
    const data = await fetchJson(GITHUB_BLOCKLIST_URL);
    if (!Array.isArray(data)) {
        throw new Error('Unexpected format: malicious.json is not an array');
    }
    return data.filter(id => typeof id === 'string' && id.includes('.'));
}

/**
 * Loads the GitHub blocklist, caching it locally and falling back to the
 * bundled malicious.json when GitHub is unreachable.
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<{ids: string[], source: string, stale: boolean}>}
 */
async function getGithubBlocklist(context) {
    const cacheFilePath = getStoragePath(context, 'github-blocklist-cache.json');
    const cache = readCache(cacheFilePath, 'ids');
    const now = Date.now();

    if (cache && (now - cache.timestamp) < GITHUB_BLOCKLIST_CACHE_TTL_MS) {
        return { ids: cache.ids, source: 'GitHub blocklist cache', stale: false };
    }

    try {
        console.log('Fetching malicious extensions blocklist from GitHub...');
        const ids = await fetchGithubBlocklist();
        if (ids.length === 0) {
            throw new Error('GitHub blocklist is empty');
        }
        writeCache(cacheFilePath, { timestamp: now, ids });
        return { ids, source: 'GitHub blocklist', stale: false };
    } catch (error) {
        console.warn('Failed to fetch GitHub blocklist:', error);
    }

    if (cache && cache.ids.length > 0) {
        return { ids: cache.ids, source: 'GitHub blocklist cache (stale)', stale: true };
    }

    const bundled = loadBundledBlocklistIds(context);
    if (bundled.length > 0) {
        return { ids: bundled, source: 'bundled malicious.json', stale: true };
    }

    return { ids: [], source: 'none', stale: true };
}

/**
 * Merges advisories by advisory ID so updated records replace older ones.
 * @param {Array} existing
 * @param {Array} fresh
 * @returns {Array}
 */
function mergeAdvisories(existing, fresh) {
    const map = new Map();
    const keyOf = entry => entry.id || `${entry.extensionId.toLowerCase()}@${entry.version}`;
    for (const entry of existing) {
        map.set(keyOf(entry), entry);
    }
    for (const entry of fresh) {
        map.set(keyOf(entry), entry);
    }
    return Array.from(map.values());
}

/**
 * Loads pkgscan.dev advisories. After the first full sync, only new or
 * updated advisories are fetched by stopping at the previous sync cursor.
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<{entries: Array, source: string, stale: boolean}>}
 */
async function getPkgscanAdvisories(context) {
    const cacheFilePath = getStoragePath(context, 'pkgscan-advisories-cache.json');
    const cache = readCache(cacheFilePath, 'entries');
    const now = Date.now();

    if (cache && (now - cache.timestamp) < PKGSCAN_CACHE_TTL_MS) {
        console.log(`Using cached pkgscan advisories (${cache.entries.length} entries)`);
        return { entries: cache.entries, source: 'pkgscan.dev cache', stale: false };
    }

    const cursor = cache && typeof cache.cursor === 'string' ? cache.cursor : null;
    const lastFullSync = cache && typeof cache.lastFullSync === 'number' ? cache.lastFullSync : 0;
    const full = !cursor || (now - lastFullSync) > PKGSCAN_FULL_SYNC_INTERVAL_MS;

    try {
        console.log(`Fetching pkgscan.dev advisories (${full ? 'full' : 'incremental'} sync)...`);
        const result = await fetchPkgscanAdvisories({ cursor, full });
        if (!result.complete) {
            throw new Error('pkgscan.dev advisory fetch was incomplete');
        }

        const entries = full
            ? result.entries
            : mergeAdvisories(cache.entries, result.entries);

        if (entries.length === 0) {
            throw new Error('pkgscan.dev returned no advisories');
        }

        const newestValue = timestampValue(result.newest);
        const cursorValue = timestampValue(cursor);
        const nextCursor = result.newest && (!cursor || (Number.isFinite(newestValue) && Number.isFinite(cursorValue) && newestValue > cursorValue))
            ? result.newest
            : cursor;

        writeCache(cacheFilePath, {
            timestamp: now,
            cursor: nextCursor || null,
            lastFullSync: full ? now : lastFullSync,
            entries
        });

        return { entries, source: 'pkgscan.dev', stale: false };
    } catch (error) {
        console.warn('Failed to fetch advisories from pkgscan.dev:', error);
    }

    if (cache && cache.entries.length > 0) {
        console.warn('Using stale pkgscan advisories cache');
        return { entries: cache.entries, source: 'pkgscan.dev cache (stale)', stale: true };
    }

    return { entries: [], source: 'none', stale: true };
}

/**
 * Combines the GitHub blocklist (base) with pkgscan.dev advisories (on top).
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<{entries: Array, source: string, stale: boolean}>}
 */
async function getMaliciousAdvisories(context) {
    const [github, pkgscan] = await Promise.all([
        getGithubBlocklist(context),
        getPkgscanAdvisories(context)
    ]);

    // pkgscan entries come first so their richer metadata wins when an ID is
    // present in both sources.
    const entries = pkgscan.entries.concat(blocklistToEntries(
        github.ids,
        'Listed on the known malicious extensions blocklist'
    ));

    const sources = [github.source, pkgscan.source].filter(source => source && source !== 'none');
    return {
        entries,
        source: sources.length > 0 ? sources.join(' + ') : 'none',
        stale: github.stale || pkgscan.stale
    };
}

/**
 * Checks all installed extensions against the GitHub blocklist and pkgscan.dev
 * advisories, then alerts the user.
 * @param {vscode.ExtensionContext} context
 */
async function checkAndReportMaliciousExtensions(context) {
    const allExtensions = vscode.extensions.all;

    try {
        const { entries, source, stale } = await getMaliciousAdvisories(context);
        const advisoryIndex = buildAdvisoryIndex(entries);

        // If no advisory data is available, there's nothing to check against.
        if (advisoryIndex.size === 0) {
            console.warn('No malicious advisory data available; skipping audit.');
            return;
        }

        const foundMaliciousExtensions = [];

        // Loop through all installed extensions and match advisories by ID and version.
        for (const extension of allExtensions) {
            const advisory = advisoryForExtension(advisoryIndex, extension);
            if (advisory) {
                foundMaliciousExtensions.push({ extension, advisory });
            }
        }

        // Report findings to the user.
        if (foundMaliciousExtensions.length > 0) {
            // Create an output channel to show detailed information.
            const outputChannel = vscode.window.createOutputChannel("Extension Security Auditor");
            outputChannel.show(true);
            outputChannel.appendLine("--- SECURITY AUDIT REPORT ---");
            outputChannel.appendLine(`Scan completed on ${new Date().toLocaleString()}`);
            outputChannel.appendLine(
                `Advisory source: ${source} (${advisoryIndex.size} malicious package${advisoryIndex.size === 1 ? '' : 's'}${stale ? ', may be stale' : ''})`
            );
            outputChannel.appendLine("--- WARNING: Malicious Extensions Found ---");

            let processedCount = 0; // Track how many extensions have been processed (uninstalled, viewed, or dismissed)
            let uninstalledCount = 0; // Track how many extensions have been uninstalled

            foundMaliciousExtensions.forEach(({ extension, advisory }) => {
                const extensionName = extension.packageJSON.displayName || extension.id;
                const installedVersion = extension.packageJSON && extension.packageJSON.version;

                outputChannel.appendLine(`- Name: ${extensionName}`);
                outputChannel.appendLine(`  ID: ${extension.id}${installedVersion ? `@${installedVersion}` : ''}`);
                if (advisory.severity) {
                    outputChannel.appendLine(`  Severity: ${advisory.severity}`);
                }
                if (advisory.title) {
                    outputChannel.appendLine(`  Advisory: ${advisory.title}`);
                }
                if (advisory.summary) {
                    outputChannel.appendLine(`  Details: ${advisory.summary}`);
                }
                if (advisory.permalink) {
                    outputChannel.appendLine(`  Report: ${advisory.permalink}`);
                }
                const reason = advisory.permalink
                    ? 'Flagged as malicious by pkgscan.dev. Uninstall unless you have verified this extension.'
                    : 'Listed on the known malicious extensions blocklist. Uninstall unless you have verified this extension.';
                outputChannel.appendLine(`  Reason: ${reason}`);
                outputChannel.appendLine("-------------------");

                // Show a warning message with uninstall and report actions.
                const actions = advisory.permalink ? ["Uninstall", "View Report"] : ["Uninstall"];
                vscode.window.showWarningMessage(
                    `Malicious extension found: '${extensionName}'`,
                    ...actions
                ).then(selection => {
                    // Increment the processed counter regardless of user choice
                    processedCount++;

                    if (selection === "Uninstall") {
                        // This command triggers the built-in Cursor uninstaller.
                        // It requires user confirmation.
                        vscode.commands.executeCommand('workbench.extensions.uninstallExtension', extension.id);
                        uninstalledCount++;
                    } else if (selection === "View Report" && advisory.permalink) {
                        vscode.env.openExternal(vscode.Uri.parse(advisory.permalink));
                    }

                    // Check if this was the last extension to be processed (uninstalled, viewed, or dismissed)
                    if (processedCount === foundMaliciousExtensions.length && uninstalledCount > 0) {
                        // Show restart prompt after all extensions have been processed
                        setTimeout(() => {
                            vscode.window.showInformationMessage(
                                'Security audit completed. Cursor needs to restart to complete uninstallations.',
                                'Restart Cursor'
                            ).then(restartSelection => {
                                if (restartSelection === 'Restart Cursor') {
                                    // Execute the restart command
                                    vscode.commands.executeCommand('workbench.action.reloadWindow');
                                }
                            });
                        }, 1000); // Small delay to ensure all commands have been processed
                    }
                });
            });

            outputChannel.appendLine("--- IMPORTANT ---");
            outputChannel.appendLine(`The detected extensions are flagged as malicious (source: ${source}). Please verify the extensions and consider uninstalling them immediately.`);
            outputChannel.appendLine("-------------------");

        } else {
            vscode.window.showInformationMessage('No known malicious extensions found. Your Cursor environment is looking good!');
        }
    } catch (error) {
        console.error('Error during security audit:', error);
        vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
    }
}

/**
 * This function is called when your extension is deactivated.
 */
function deactivate() {}

// Module exports
module.exports = {
    activate,
    deactivate
}