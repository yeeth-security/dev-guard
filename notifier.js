/**
 * Notification ledger, batching, and removal modes (`auto`, `prompt`, `warn`).
 *
 * Why this file exists:
 *   With 5-minute background polling, showing a popup for every flagged
 *   extension on every poll would spam the user. We need a persistent ledger
 *   so each `(extensionId@version, advisoryId)` pair is notified at most once
 *   unless its severity increases or the user runs a manual check.
 *
 * How auto-uninstall works:
 *   VS Code's built-in command `workbench.extensions.uninstallExtension`
 *   uninstalls an extension directly without a confirmation dialog. Because an
 *   already-activated extension stays in memory until the window reloads, the
 *   summary notice tells the user to reload and provides a "Reload Window" button.
 */

const LEDGER_KEY = 'devGuard.notificationLedger';
const AUTO_DISCLOSURE_KEY = 'devGuard.autoRemovalNoticeShown';
const ERROR_TOAST_KEY = 'devGuard.lastErrorToastAt';
const ERROR_TOAST_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cleanup guide shown after a removal: rotate secrets, check for persistence, etc.
// Linked from the toasts here and from the pane's Removed / Audit log entries.
const REMOVAL_GUIDE_URL = 'https://yeethsecurity.com/guides/vscode-extension-malware/#remove';
const GUIDE_BUTTON = 'What to do next';

/** Opens the cleanup guide and records where the click came from. */
function openRemovalGuide(vscodeApi, telemetry, from) {
    void vscodeApi.env.openExternal(vscodeApi.Uri.parse(REMOVAL_GUIDE_URL));
    telemetry?.record('removal_guide_opened', { from });
}

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function severityRank(severity) {
    return SEVERITY_RANK[String(severity || '').toLowerCase()] || 0;
}

/**
 * Builds the unique ledger key for an installed extension + advisory pair.
 */
function ledgerKeyFor(finding) {
    const extId = String(finding.extension.id || '').toLowerCase();
    const ver = (finding.extension.packageJSON && finding.extension.packageJSON.version) || '*';
    const advId = (finding.advisory && finding.advisory.id) || 'default';
    return `${extId}@${ver}::${advId}`;
}

/**
 * Decides if a finding should notify the user on this cycle.
 * Manual checks always notify. Background checks only notify on a new pair
 * or when the advisory's severity increased since the last notification.
 */
function shouldNotifyFinding(ledger, finding, trigger) {
    if (trigger === 'manual') return true;
    const prev = ledger && ledger[ledgerKeyFor(finding)];
    if (!prev) return true;
    return severityRank(finding.advisory && finding.advisory.severity) > severityRank(prev.severity);
}

function filterActionableFindings(ledger, findings, trigger) {
    return (Array.isArray(findings) ? findings : []).filter(f => shouldNotifyFinding(ledger, f, trigger));
}

function recordFindingsInLedger(ledger, findings, action, now = Date.now()) {
    const next = { ...(ledger || {}) };
    for (const finding of Array.isArray(findings) ? findings : []) {
        next[ledgerKeyFor(finding)] = {
            severity: (finding.advisory && finding.advisory.severity) || 'unknown',
            action,
            updatedAt: now
        };
    }
    return next;
}

function loadLedger(context) {
    try {
        const raw = context && context.globalState ? context.globalState.get(LEDGER_KEY) : null;
        return raw && typeof raw === 'object' ? { ...raw } : {};
    } catch (_error) {
        return {};
    }
}

function saveLedger(context, ledger) {
    try {
        if (context && context.globalState) void context.globalState.update(LEDGER_KEY, ledger);
    } catch (_error) {
        // Ignore storage write errors.
    }
}

/**
 * Shows a one-time disclosure when `devGuard.removalMode` is `auto`.
 */
function showAutoModeDisclosureOnce(context, vscodeApi, removalMode = 'auto') {
    if (removalMode !== 'auto' || !context || !context.globalState || !vscodeApi) return;
    try {
        if (context.globalState.get(AUTO_DISCLOSURE_KEY)) return;
        void context.globalState.update(AUTO_DISCLOSURE_KEY, true);
    } catch (_error) {
        return;
    }
    void vscodeApi.window.showInformationMessage(
        'dev-guard automatically removes extensions flagged as malicious by pkgscan.dev. You can change `devGuard.removalMode` to "prompt" or "warn" in Settings.',
        'Change to Prompt'
    ).then(choice => {
        if (choice === 'Change to Prompt' && vscodeApi.workspace) {
            const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
            void vscodeApi.workspace.getConfiguration('devGuard').update('removalMode', 'prompt', target);
        }
    });
}

/**
 * Rate-limits background error popups to at most one per 24 hours.
 */
function notifyAuditError(context, vscodeApi, trigger, now = Date.now()) {
    if (!vscodeApi || !vscodeApi.window) return false;
    if (trigger !== 'manual' && context && context.globalState) {
        const last = Number(context.globalState.get(ERROR_TOAST_KEY)) || 0;
        if (now - last < ERROR_TOAST_COOLDOWN_MS) return false;
        void context.globalState.update(ERROR_TOAST_KEY, now);
    }
    void vscodeApi.window.showErrorMessage('Error during security audit. Check the console for details.');
    return true;
}

/**
 *Uninstalls a list of findings and prompts to reload the window.
 */
async function uninstallFindings(vscodeApi, findings, telemetry, eventName) {
    const removed = [];
    const failed = [];
    for (const item of findings) {
        try {
            await vscodeApi.commands.executeCommand('workbench.extensions.uninstallExtension', item.extension.id);
            const stillPresent = Array.isArray(vscodeApi.extensions && vscodeApi.extensions.all)
                && vscodeApi.extensions.all.some(e => e.id.toLowerCase() === item.extension.id.toLowerCase());
            removed.push({ ...item, pendingReload: stillPresent });
            telemetry?.record(eventName, {
                extension_id: item.extension.id,
                severity: item.advisory.severity || 'unknown'
            });
        } catch (error) {
            console.warn(`Could not uninstall ${item.extension.id}:`, error);
            failed.push(item);
        }
    }
    return { removed, failed };
}

/**
 * Handles audit findings according to `removalMode` (`auto`, `prompt`, `warn`)
 * with one batched notification per cycle and ledger de-duplication.
 *
 * `onRemoved(items, action)` is optional. The side pane uses it to log every
 * removal (auto or user-clicked) to the scan history.
 *
 * Ledger rules:
 *   - `auto` mode uninstalls EVERY finding passed in, even if the ledger has
 *     seen it before. A finding only reaches this function if the extension
 *     is really on disk (see allowlist.js), so a repeat means the user
 *     reinstalled it. We remove it again until they allowlist it.
 *   - The ledger still gates `prompt` and `warn` toasts, and the fallback
 *     prompt when an auto-uninstall fails, so background polls never spam.
 */
async function handleAuditFindings({ context, vscodeApi, findings, trigger, removalMode = 'auto', telemetry, now = Date.now(), onRemoved }) {
    const reportRemoved = (items, action) => { try { onRemoved?.(items, action); } catch (_e) { /* never break the audit */ } };
    let ledger = loadLedger(context);
    const all = Array.isArray(findings) ? findings : [];
    const actionable = removalMode === 'auto' ? all : filterActionableFindings(ledger, all, trigger);

    if (actionable.length === 0) {
        if (trigger === 'manual' && all.length === 0) {
            vscodeApi.window.showInformationMessage('No known malicious extensions found. Your IDE environment is looking good!');
        }
        return { notified: 0, removed: 0 };
    }

    const firstReportUrl = (actionable.find(f => f.advisory && f.advisory.permalink) || {}).advisory?.permalink || null;
    const names = actionable.map(f => `'${(f.extension.packageJSON && f.extension.packageJSON.displayName) || f.extension.id}'`).join(', ');
    telemetry?.record('advisory_notified', { count: actionable.length, mode: removalMode, trigger });

    let promptList = actionable;
    let removedCount = 0;

    if (removalMode === 'auto') {
        const { removed, failed } = await uninstallFindings(vscodeApi, actionable, telemetry, 'auto_uninstalled');
        removedCount = removed.length;
        if (removed.length > 0) {
            ledger = recordFindingsInLedger(ledger, removed, 'auto-uninstalled', now);
            saveLedger(context, ledger);
            reportRemoved(removed, 'auto');
            const removedNames = removed.map(f => `'${(f.extension.packageJSON && f.extension.packageJSON.displayName) || f.extension.id}'`).join(', ');
            // "What to do next" opens the cleanup guide: a removed extension may
            // already have run, so the user should rotate secrets and check for leftovers.
            const buttons = firstReportUrl ? ['Reload Window', GUIDE_BUTTON, 'View Report'] : ['Reload Window', GUIDE_BUTTON];
            vscodeApi.window.showWarningMessage(
                `dev-guard removed malicious extension(s) flagged by pkgscan.dev: ${removedNames}. Reload the window to unload them from memory. `
                + 'It will be removed again if reinstalled unless you add it to devGuard.allowlist.',
                ...buttons
            ).then(sel => {
                if (sel === 'Reload Window') vscodeApi.commands.executeCommand('workbench.action.reloadWindow');
                else if (sel === GUIDE_BUTTON) openRemovalGuide(vscodeApi, telemetry, 'auto_toast');
                else if (sel === 'View Report' && firstReportUrl) vscodeApi.env.openExternal(vscodeApi.Uri.parse(firstReportUrl));
            });
        }
        // Failed uninstalls fall back to a prompt, but only once per
        // (extension, advisory) so a stuck extension does not spam every poll.
        promptList = filterActionableFindings(ledger, failed, trigger);
    }

    if (promptList.length > 0 && removalMode !== 'warn') {
        ledger = recordFindingsInLedger(ledger, promptList, 'prompted', now);
        saveLedger(context, ledger);
        const promptNames = promptList.map(f => `'${(f.extension.packageJSON && f.extension.packageJSON.displayName) || f.extension.id}'`).join(', ');
        const buttons = firstReportUrl ? ['Uninstall', 'View Report'] : ['Uninstall'];
        vscodeApi.window.showWarningMessage(
            `Malicious extension(s) flagged by pkgscan.dev: ${promptNames}`,
            ...buttons
        ).then(async sel => {
            if (sel === 'Uninstall') {
                const { removed } = await uninstallFindings(vscodeApi, promptList, telemetry, 'uninstall_clicked');
                if (removed.length > 0) {
                    reportRemoved(removed, 'prompt');
                    vscodeApi.window.showInformationMessage(
                        'Security audit completed. Reload the window to finish uninstalling extensions.',
                        'Reload Window', GUIDE_BUTTON
                    ).then(r => {
                        if (r === 'Reload Window') vscodeApi.commands.executeCommand('workbench.action.reloadWindow');
                        else if (r === GUIDE_BUTTON) openRemovalGuide(vscodeApi, telemetry, 'prompt_toast');
                    });
                }
            } else if (sel === 'View Report' && firstReportUrl) {
                vscodeApi.env.openExternal(vscodeApi.Uri.parse(firstReportUrl));
                telemetry?.record('report_viewed', { extension_id: promptList[0].extension.id, severity: promptList[0].advisory.severity || 'unknown' });
            }
        });
    } else if (promptList.length > 0 && removalMode === 'warn') {
        ledger = recordFindingsInLedger(ledger, promptList, 'warned', now);
        saveLedger(context, ledger);
        const buttons = firstReportUrl ? ['View Report'] : [];
        vscodeApi.window.showWarningMessage(`Malicious extension(s) flagged by pkgscan.dev: ${names}`, ...buttons).then(sel => {
            if (sel === 'View Report' && firstReportUrl) vscodeApi.env.openExternal(vscodeApi.Uri.parse(firstReportUrl));
        });
    }

    return { notified: actionable.length, removed: removedCount };
}

module.exports = {
    LEDGER_KEY,
    AUTO_DISCLOSURE_KEY,
    ERROR_TOAST_KEY,
    REMOVAL_GUIDE_URL,
    SEVERITY_RANK,
    severityRank,
    ledgerKeyFor,
    shouldNotifyFinding,
    filterActionableFindings,
    recordFindingsInLedger,
    loadLedger,
    saveLedger,
    showAutoModeDisclosureOnce,
    notifyAuditError,
    uninstallFindings,
    handleAuditFindings
};
