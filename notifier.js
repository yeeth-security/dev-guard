/**
 * Notification ledger, batching, and removal modes (`auto`, `manual`, `warn`).
 *
 * Why this file exists:
 *   With 5-minute background polling, showing a popup for every flagged
 *   extension on every poll would spam the user. Manual and warn mode use a
 *   ledger so each `(extensionId@version, advisoryId)` pair is notified at
 *   most once unless its severity increases or the user runs a manual check.
 *   Auto mode shows the reload toast again on a later scan when it is not
 *   already on screen, because the user has not reloaded.
 *
 * How auto-uninstall works:
 *   VS Code's built-in command `workbench.extensions.uninstallExtension`
 *   uninstalls an extension directly without a confirmation dialog. Because an
 *   already-activated extension stays in memory until the window reloads, the
 *   summary notice tells the user to reload and provides a "Reload Window" button.
 */

const { openInEditor } = require('./openUrl');

const LEDGER_KEY = 'devGuard.notificationLedger';
const AUTO_DISCLOSURE_KEY = 'devGuard.autoRemovalNoticeShown';
const ERROR_TOAST_KEY = 'devGuard.lastErrorToastAt';
const ERROR_TOAST_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cleanup guide shown after a removal: rotate secrets, check for persistence, etc.
// Linked from the toasts here and from Extension threats / Audit log entries.
const REMOVAL_GUIDE_URL = 'https://yeethsecurity.com/guides/vscode-extension-malware/#remove';
const GUIDE_BUTTON = 'What to do next';

/** Opens the cleanup guide in the editor and records where the click came from. */
function openRemovalGuide(vscodeApi, telemetry, from) {
    openInEditor(vscodeApi, REMOVAL_GUIDE_URL);
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
 * Manual checks always notify. So does a scan started because an extension
 * just left the allowlist: the old ledger row must not keep that scan quiet.
 * Background checks only notify on a new pair or when the advisory's
 * severity increased since the last notification.
 */
function shouldNotifyFinding(ledger, finding, trigger) {
    if (trigger === 'manual' || trigger === 'unallow') return true;
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
 * Drops ledger rows for these extension ids.
 * An id that was allowlisted and then removed in Settings must be treated as
 * new, or the next scan stays quiet because it was already notified.
 * Keys look like `publisher.name@version::advisoryId`.
 */
function forgetExtensionsInLedger(context, extensionIds) {
    const ids = new Set((extensionIds || []).map(id => String(id || '').toLowerCase()).filter(Boolean));
    if (ids.size === 0) return 0;
    const ledger = loadLedger(context);
    let dropped = 0;
    for (const key of Object.keys(ledger)) {
        if (key.startsWith('file::')) continue;
        const extId = key.split('@')[0];
        if (ids.has(extId)) {
            delete ledger[key];
            dropped += 1;
        }
    }
    if (dropped > 0) saveLedger(context, ledger);
    return dropped;
}

/**
 * Drops file-threat ledger rows whose SHA-256 was just removed from
 * `devGuard.allowedFiles`. Keys look like `file::<path>::<sha256>`.
 */
function forgetFileHashesInLedger(context, hashes) {
    const wanted = new Set((hashes || []).map(h => String(h || '').toLowerCase()).filter(Boolean));
    if (wanted.size === 0) return 0;
    const ledger = loadLedger(context);
    let dropped = 0;
    for (const key of Object.keys(ledger)) {
        if (!key.startsWith('file::')) continue;
        const hash = key.slice(key.lastIndexOf('::') + 2);
        if (wanted.has(hash)) {
            delete ledger[key];
            dropped += 1;
        }
    }
    if (dropped > 0) saveLedger(context, ledger);
    return dropped;
}

/**
 * Shows a one-time disclosure when `devGuard.removalMode` is `auto`.
 */
function showAutoModeDisclosureOnce(context, vscodeApi, removalMode = 'auto', telemetry) {
    if (removalMode !== 'auto' || !context || !context.globalState || !vscodeApi) return;
    try {
        if (context.globalState.get(AUTO_DISCLOSURE_KEY)) return;
        void context.globalState.update(AUTO_DISCLOSURE_KEY, true);
    } catch (_error) {
        return;
    }
    void vscodeApi.window.showInformationMessage(
        'dev-guard automatically removes extensions flagged as malicious by pkgscan.dev. You can change `devGuard.removalMode` to "manual" or "warn" in Settings.',
        'Change to Manual'
    ).then(choice => {
        if (choice === 'Change to Manual' && vscodeApi.workspace) {
            const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
            void vscodeApi.workspace.getConfiguration('devGuard').update('removalMode', 'manual', target);
            telemetry?.record('mode_changed', { mode: 'manual', from: 'auto_disclosure' });
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
 * Handles audit findings according to `removalMode` (`auto`, `manual`, `warn`)
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
 *   - The ledger still gates `manual` and `warn` toasts, so background polls
 *     do not repeat those. Auto mode shows the reload toast and a failed
 *     uninstall prompt again on the next scan when that toast is not already up.
 */
async function handleAuditFindings({ context, vscodeApi, findings, trigger, removalMode = 'auto', telemetry, now = Date.now(), onRemoved, pendingReload = false }) {
    const reportRemoved = (items, action) => { try { onRemoved?.(items, action); } catch (_e) { /* never break the audit */ } };
    let ledger = loadLedger(context);
    const all = Array.isArray(findings) ? findings : [];
    const actionable = removalMode === 'auto' ? all : filterActionableFindings(ledger, all, trigger);

    if (actionable.length === 0) {
        // A reload is still waiting. "Looking good" would hide that.
        if (trigger === 'manual' && all.length === 0 && !pendingReload) {
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
            // One reload toast at a time. A later scan shows it again only
            // when it is not already on screen (the user closed nothing by
            // reloading). "What to do next" opens the cleanup guide.
            showReloadNotice(vscodeApi, telemetry, {
                names: removedNames,
                reportUrl: firstReportUrl,
                extensionId: removed[0].extension.id,
                severity: removed[0].advisory.severity || 'unknown',
                from: 'auto_toast'
            });
        }
        // A failed uninstall is still a live threat. The next scan shows the
        // prompt again unless that prompt is already up.
        promptList = hasOpenNotice('extension') ? [] : failed;
    }

    if (promptList.length > 0 && removalMode !== 'warn') {
        ledger = recordFindingsInLedger(ledger, promptList, 'prompted', now);
        saveLedger(context, ledger);
        const promptNames = promptList.map(f => `'${(f.extension.packageJSON && f.extension.packageJSON.displayName) || f.extension.id}'`).join(', ');
        const buttons = firstReportUrl ? ['Uninstall', 'View Report'] : ['Uninstall'];
        showActionNotice(
            vscodeApi,
            `Malicious extension(s) flagged by pkgscan.dev: ${promptNames}`,
            buttons,
            async sel => {
                if (sel === 'Uninstall') {
                    const { removed } = await uninstallFindings(vscodeApi, promptList, telemetry, 'uninstall_clicked');
                    if (removed.length > 0) {
                        reportRemoved(removed, 'manual');
                        showNoticeUntilAction(
                            (message, ...items) => vscodeApi.window.showInformationMessage(message, ...items),
                            'Security audit completed. Reload the window to finish uninstalling extensions.',
                            ['Reload Window', GUIDE_BUTTON],
                            r => {
                                if (r === 'Reload Window') {
                                    telemetry?.record('reload_clicked', { from: 'manual_toast' });
                                    vscodeApi.commands.executeCommand('workbench.action.reloadWindow');
                                } else if (r === GUIDE_BUTTON) {
                                    openRemovalGuide(vscodeApi, telemetry, 'manual_toast');
                                }
                            }
                        );
                    }
                } else if (sel === 'View Report' && firstReportUrl) {
                    openInEditor(vscodeApi, firstReportUrl);
                    telemetry?.record('report_viewed', { extension_id: promptList[0].extension.id, severity: promptList[0].advisory.severity || 'unknown' });
                    telemetry?.record('pkgscan_opened', { source: 'manual_toast', extension_id: promptList[0].extension.id });
                }
                // The X is not a decision. The toast is shown again, so this
                // is not a refused uninstall.
            },
            'extension'
        );
    } else if (promptList.length > 0 && removalMode === 'warn') {
        ledger = recordFindingsInLedger(ledger, promptList, 'warned', now);
        saveLedger(context, ledger);
        const buttons = firstReportUrl ? ['View Report'] : [];
        showActionNotice(vscodeApi, `Malicious extension(s) flagged by pkgscan.dev: ${names}`, buttons, sel => {
            if (sel === 'View Report' && firstReportUrl) {
                openInEditor(vscodeApi, firstReportUrl);
                telemetry?.record('report_viewed', { extension_id: promptList[0].extension.id, severity: promptList[0].advisory.severity || 'unknown' });
                telemetry?.record('pkgscan_opened', { source: 'warn_toast', extension_id: promptList[0].extension.id });
            }
        }, 'extension');
    }

    return { notified: actionable.length, removed: removedCount };
}

/** Builds a ledger key for a local file threat (`file::<path>::<sha256>`). */
function fileLedgerKeyFor(finding) {
    const fp = String((finding && finding.filePath) || '').toLowerCase();
    const hash = String((finding && finding.sha256) || 'none').toLowerCase();
    return `file::${fp}::${hash}`;
}

const SEE_MORE_BUTTON = 'See more';

/**
 * Toast for a scan that needs a decision. This is `showErrorMessage`, not a
 * dialog. VS Code hides a warning toast after a few seconds. An error toast
 * that has actions stays in the corner until the user clicks one or dismisses
 * the toast with the X. Clicking a button always closes it, so a choice that
 * does not resolve the threat is shown again. The X closes the toast with no
 * choice. That is not an action, so the same toast is shown again.
 *
 * `kind` is `file`, `extension`, or `reload`. The pane uses it to dismiss the
 * matching toast when the user resolves that threat there.
 */
function showActionNotice(vscodeApi, message, buttons, onChoice, kind) {
    showNoticeUntilAction(
        (text, ...items) => vscodeApi.window.showErrorMessage(text, ...items),
        message,
        buttons,
        onChoice,
        kind
    );
}

// No choice means the user clicked the X. That is not an action, so the toast
// comes back. These buttons only open something else, so they come back too.
// Quarantine, Uninstall, and Reload Window are the decision and stay closed.
function choiceKeepsNoticeOpen(choice) {
    if (choice == null) return true;
    return choice === GUIDE_BUTTON || choice === 'View Report' || choice === 'Inspect File' || choice === SEE_MORE_BUTTON;
}

function hasOpenNotice(kind) {
    for (const handle of openNotices) {
        if (!handle.closed && handle.kind === kind) return true;
    }
    return false;
}

function reloadNoticeMessage(names) {
    const who = names ? `: ${names}` : '';
    return `dev-guard removed malicious extension(s) flagged by pkgscan.dev${who}. Reload the window to unload them from memory. `
        + 'It will be removed again if reinstalled unless you add it to devGuard.allowlist.';
}

/**
 * The auto-remove toast. Skipped when one is already up, so a rescan does
 * not stack a second copy. Shown again when the previous one is gone and
 * the window still has not been reloaded.
 */
function showReloadNotice(vscodeApi, telemetry, { names, reportUrl, extensionId, severity, from }) {
    if (!vscodeApi || !vscodeApi.window || hasOpenNotice('reload')) return false;
    const buttons = reportUrl ? ['Reload Window', GUIDE_BUTTON, 'View Report'] : ['Reload Window', GUIDE_BUTTON];
    showActionNotice(vscodeApi, reloadNoticeMessage(names), buttons, sel => {
        if (sel === 'Reload Window') {
            telemetry?.record('reload_clicked', { from });
            vscodeApi.commands.executeCommand('workbench.action.reloadWindow');
        } else if (sel === GUIDE_BUTTON) {
            openRemovalGuide(vscodeApi, telemetry, from);
        } else if (sel === 'View Report' && reportUrl) {
            openInEditor(vscodeApi, reportUrl);
            telemetry?.record('report_viewed', { extension_id: extensionId, severity: severity || 'unknown' });
            telemetry?.record('pkgscan_opened', { source: from, extension_id: extensionId });
        }
    }, 'reload');
    return true;
}

/** Next auto scan, after the extension is already off the installed list. */
function remindPendingReload(vscodeApi, telemetry, notice) {
    if (!notice) return false;
    return showReloadNotice(vscodeApi, telemetry, {
        names: notice.names,
        reportUrl: notice.reportUrl || null,
        extensionId: notice.extensionId,
        severity: notice.severity,
        from: 'auto_rescan'
    });
}

// Toasts still waiting on a click. `showErrorMessage` has no close handle,
// so the pane marks the handle closed and then hides the toast widget.
const openNotices = new Set();

function showNoticeUntilAction(show, message, buttons, onChoice, kind = 'action') {
    const handle = { closed: false, kind, generation: 0 };
    const open = () => {
        if (handle.closed) return;
        // A newer show of this same notice makes an older click a no-op.
        const generation = ++handle.generation;
        Promise.resolve(show(message, ...buttons)).then(async choice => {
            if (handle.closed || handle.generation !== generation) return;
            try {
                await onChoice?.(choice);
            } catch (_error) { /* a click handler must not drop the toast */ }
            if (handle.closed || handle.generation !== generation) return;
            if (choiceKeepsNoticeOpen(choice)) open();
            else openNotices.delete(handle);
        });
    };
    handle.reopen = open;
    openNotices.add(handle);
    open();
}

/**
 * The pane already resolved this threat (uninstall, allow, quarantine).
 * Close the matching toast. A click that is not the decision still re-shows
 * its own toast; this only runs for a real action in the pane.
 *
 * `showErrorMessage` cannot target one toast. We focus the newest toast and
 * clear it, then hide whatever is still in the corner. Any Dev-Guard toast
 * that is still waiting is shown again.
 */
async function dismissActionNotices(vscodeApi, kind) {
    const closing = [];
    for (const handle of openNotices) {
        if (kind && handle.kind !== kind) continue;
        handle.closed = true;
        closing.push(handle);
    }
    for (const handle of closing) openNotices.delete(handle);
    if (closing.length === 0) return;
    // The toast path clears this when Quarantine is clicked. The pane path
    // has to do the same, or a restored file would stay silent.
    if (kind === 'file') shownFileNoticeKeys.clear();

    for (const handle of openNotices) {
        if (!handle.closed) handle.generation += 1;
    }

    const commands = vscodeApi && vscodeApi.commands;
    const run = async command => {
        if (!commands || typeof commands.executeCommand !== 'function') return;
        try { await commands.executeCommand(command); } catch (_error) { /* host has no such command */ }
    };
    await run('notifications.focusToasts');
    await run('notification.clear');
    await run('notifications.hideToasts');

    for (const handle of openNotices) {
        if (!handle.closed && typeof handle.reopen === 'function') handle.reopen();
    }
}

/** Test helper. Marks every open toast closed so a later case starts clean. */
function resetOpenActionNotices() {
    for (const handle of openNotices) handle.closed = true;
    openNotices.clear();
}

// Files we already put a toast on screen for during this window. A save of
// the same file must not open another one. The set is cleared when tests
// start a new case, and when the user quarantines so a restore can warn again.
const shownFileNoticeKeys = new Set();

function resetShownFileNotices() {
    shownFileNoticeKeys.clear();
}

/**
 * One warning for local `.vscode/` profile or workspace file threats.
 * Buttons: Quarantine, Inspect File, and See more. Allowing a file stays in
 * the Dev-Guard pane. The toast stays until the user quarantines the file.
 * Closing it with the X shows it again.
 * A later scan shows it again when that toast is not already on screen.
 */
async function handleFileFindings({
    context, vscodeApi, findings, trigger, telemetry, now = Date.now(),
    onQuarantine, onInspect, onOpenPane
}) {
    if (!vscodeApi || !vscodeApi.window) return { notified: 0 };
    let ledger = loadLedger(context);
    const all = Array.isArray(findings) ? findings : [];
    const actionable = all.filter(f => {
        const key = fileLedgerKeyFor(f);
        // The toast is already asking about this file. A later scan must
        // not stack another one. If that toast is gone, the file is still
        // a threat and the user has not quarantined it, so show it again.
        if (shownFileNoticeKeys.has(key) && hasOpenNotice('file')) return false;
        return true;
    });

    if (actionable.length === 0) return { notified: 0 };

    for (const f of actionable) {
        const key = fileLedgerKeyFor(f);
        shownFileNoticeKeys.add(key);
        ledger[key] = { severity: f.severity || 'high', action: 'file-alerted', updatedAt: now };
        const topRule = (f.matches && f.matches[0] && f.matches[0].rule) || 'UNKNOWN';
        telemetry?.recordOnce?.(`file_threat:${f.sha256 || f.fileName}`, 'file_threat_found', {
            scope: f.scope || 'workspace',
            severity: f.severity || 'high',
            rule: topRule
        });
    }
    saveLedger(context, ledger);

    const labels = actionable.map(f => {
        const rules = [...new Set((f.matches || []).map(m => m.rule))].join(', ');
        return `'${f.displayPath || f.fileName}' [${String(f.severity || 'high').toUpperCase()}${rules ? `: ${rules}` : ''}]`;
    }).join(', ');

    const message = `dev-guard detected suspicious payload: ${labels}.`;

    // One toast. Quarantine closes it. The X, Inspect, and See more show it again.
    showActionNotice(vscodeApi, message, ['Quarantine', 'Inspect File', SEE_MORE_BUTTON], async choice => {
        if (choice === 'Quarantine') {
            for (const f of actionable) shownFileNoticeKeys.delete(fileLedgerKeyFor(f));
            telemetry?.record('file_threat_action', { action: 'quarantine', count: actionable.length, from: 'toast' });
            await onQuarantine?.(actionable);
            return;
        }
        if (choice === 'Inspect File') {
            telemetry?.record('file_threat_action', { action: 'inspect', count: actionable.length, from: 'toast' });
            await onInspect?.(actionable[0]);
        } else if (choice === SEE_MORE_BUTTON) {
            telemetry?.record('file_threat_action', { action: 'open_pane', count: actionable.length, from: 'toast' });
            await onOpenPane?.();
        }
    }, 'file');

    return { notified: actionable.length };
}

module.exports = {
    LEDGER_KEY,
    AUTO_DISCLOSURE_KEY,
    ERROR_TOAST_KEY,
    REMOVAL_GUIDE_URL,
    GUIDE_BUTTON,
    openRemovalGuide,
    SEVERITY_RANK,
    severityRank,
    ledgerKeyFor,
    fileLedgerKeyFor,
    shouldNotifyFinding,
    filterActionableFindings,
    recordFindingsInLedger,
    loadLedger,
    saveLedger,
    forgetExtensionsInLedger,
    forgetFileHashesInLedger,
    showAutoModeDisclosureOnce,
    notifyAuditError,
    uninstallFindings,
    handleAuditFindings,
    handleFileFindings,
    showActionNotice,
    dismissActionNotices,
    remindPendingReload,
    resetOpenActionNotices,
    resetShownFileNotices,
    SEE_MORE_BUTTON
};
