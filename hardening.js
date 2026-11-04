/**
 * Editor security health check ("Harden this editor").
 *
 * Why this file exists:
 *   Malicious repositories often use `.vscode/tasks.json` or `.vscode/extensions.json`
 *   to run code or nudge users to install shady extensions as soon as a folder opens.
 *   This module defines five built-in editor settings that protect the user and
 *   checks whether each one is in a safe state.
 *
 * How it works:
 *   - Pure module with no `vscode` import so every rule is easy to unit test.
 *   - Reads each setting through `inspect()`, never `get()`. We only look at
 *     `globalValue` (the user's choice) or `defaultValue` (the editor default).
 *     Workspace overrides are ignored so a repo cannot fake a safe status.
 *   - Probes setting support with `defaultValue !== undefined`. If an older
 *     editor or fork does not have a setting, we report `unavailable`.
 *   - Reports each check as `satisfied`, `unsatisfied`, or `unavailable`.
 */

const AUTOMATIC_TASKS = 'off';
const AUTO_UPDATE_DELAY = 24;
const CURSOR_COOLDOWN_KEY = 'extensions.installCooldownHours';
const TRUST_STARTUP_PROMPT = 'always';
const IGNORE_RECOMMENDATIONS = true;
const WORKSPACE_TRUST_ENABLED = true;

const COOLDOWN_TOOLTIP =
    'Applies to auto-updates of enabled extensions only. Trusted publishers are not delayed, ' +
    'first-time installs are not delayed, and this does nothing while auto-update is off.';

/**
 * The five editor security checks shown in the Setup health check list.
 */
const CHECKS = Object.freeze([
    {
        id: 'automaticTasks',
        key: 'task.allowAutomaticTasks',
        icon: 'tasks',
        label: 'Auto-run tasks',
        recommended: AUTOMATIC_TASKS,
        isSafe: value => String(value).toLowerCase() === AUTOMATIC_TASKS,
        format: value => (String(value).toLowerCase() === 'on' ? 'On' : 'Off'),
        safeSub: 'No recommended actions · Auto-run is off',
        unsafeSub: 'Action needed · Tasks can run when a folder opens',
        safeDetail: 'Tasks in a folder cannot run just because the folder opened.',
        unsafeDetail: 'A task in .vscode/tasks.json can run as soon as the folder opens.',
        tooltip: 'VS Code 1.109+ defaults to off; anyone who turned it on earlier keeps it on.'
    },
    {
        id: 'autoUpdateDelay',
        key: 'extensions.autoUpdateDelay',
        cursorKey: CURSOR_COOLDOWN_KEY,
        icon: 'updates',
        label: 'Auto-update delay',
        recommended: AUTO_UPDATE_DELAY,
        isSafe: value => Number(value) >= AUTO_UPDATE_DELAY,
        format: value => (Number(value) > 0 ? `${Number(value)} h` : 'Off'),
        safeSub: value => `No recommended actions · Updates wait ${Number(value)} h before installing`,
        unsafeSub: value => (Number(value) > 0
            ? `Action needed · Delay is ${Number(value)} h (below ${AUTO_UPDATE_DELAY} h)`
            : 'Action needed · Extension updates install with no delay'),
        unavailableSub: 'Not available in this editor (needs VS Code 1.125+ or Cursor)',
        safeDetail: value => `Extension updates wait ${Number(value)} h before they install, leaving a window to pull a bad one.`,
        unsafeDetail: value => (Number(value) > 0
            ? `Extension updates only wait ${Number(value)} h before installing, which is below the recommended ${AUTO_UPDATE_DELAY} h minimum.`
            : 'Extension updates install right away, with no window to pull a bad one.'),
        unavailableDetail: 'Needs VS Code 1.125+ or Cursor (extensions.installCooldownHours).',
        tooltip: COOLDOWN_TOOLTIP
    },
    {
        id: 'trustPrompt',
        key: 'security.workspace.trust.startupPrompt',
        icon: 'folder',
        label: 'Folder trust prompt',
        recommended: TRUST_STARTUP_PROMPT,
        isSafe: value => String(value).toLowerCase() === TRUST_STARTUP_PROMPT,
        format: value => {
            const text = String(value || '').toLowerCase();
            return text ? text.charAt(0).toUpperCase() + text.slice(1) : 'Unknown';
        },
        safeSub: 'No recommended actions · Always asks before trusting',
        unsafeSub: 'Action needed · Folders can be trusted without asking',
        safeDetail: 'Opening a folder always asks before it is trusted.',
        unsafeDetail: 'A folder can be trusted without the editor asking first.',
        tooltip: 'Trust becomes a decision instead of a default.'
    },
    {
        id: 'ignoreRecommendations',
        key: 'extensions.ignoreRecommendations',
        icon: 'apps',
        label: 'Install suggestions',
        recommended: IGNORE_RECOMMENDATIONS,
        isSafe: value => value === true,
        format: value => (value === true ? 'Hidden' : 'Shown'),
        safeSub: 'No recommended actions · Repo suggestions are hidden',
        unsafeSub: 'Action needed · Repos can nudge you to install extensions',
        safeDetail: 'A repository cannot nudge you to install the extensions it lists.',
        unsafeDetail: '.vscode/extensions.json can nudge you to install the extensions it lists.',
        tooltip: 'Stops a repository from recommending its own extensions.'
    },
    {
        id: 'workspaceTrust',
        key: 'security.workspace.trust.enabled',
        icon: 'lock',
        label: 'Workspace Trust',
        recommended: WORKSPACE_TRUST_ENABLED,
        isSafe: value => value === true,
        format: value => (value === true ? 'On' : 'Off'),
        safeSub: 'No recommended actions · Restricted Mode is enabled',
        unsafeSub: 'Action needed · Restricted Mode is turned off',
        safeDetail: 'Restricted Mode is available to block terminals, tasks, and debugging.',
        unsafeDetail: 'Restricted Mode is off, so an unknown folder is never sandboxed.',
        tooltip: 'This is the base switch for everything else in this section.'
    }
]);

/** Splits a dotted setting key into `{ section, name }` for `getConfiguration`. */
function splitSettingKey(key) {
    const text = String(key || '');
    const dot = text.lastIndexOf('.');
    return dot > 0 ? { section: text.slice(0, dot), name: text.slice(dot + 1) } : { section: undefined, name: text };
}

function safeInspect(inspectFn, key) {
    if (typeof inspectFn !== 'function') return undefined;
    try { return inspectFn(key) || undefined; } catch (_e) { return undefined; }
}

function errorText(error) {
    const message = error && (error.message || error) ? String(error.message || error).trim() : '';
    return (message || 'The editor rejected this change.').slice(0, 200);
}

function isCursorApp(appName) {
    return typeof appName === 'string' && appName.toLowerCase().includes('cursor');
}

/**
 * Resolves the active setting key and `inspect()` metadata for a check.
 * Cursor uses `extensions.installCooldownHours` instead of VS Code's
 * `extensions.autoUpdateDelay`. We check `options.appName` first and also
 * fall back across both keys via `defaultValue !== undefined`.
 */
function resolveCheckKey(inspectFn, check, options = {}) {
    if (!check.cursorKey) return { key: check.key, info: safeInspect(inspectFn, check.key) };
    const preferCursor = isCursorApp(options && options.appName);
    const primaryKey = preferCursor ? check.cursorKey : check.key;
    const secondaryKey = preferCursor ? check.key : check.cursorKey;

    const primaryInfo = safeInspect(inspectFn, primaryKey);
    if (primaryInfo && primaryInfo.defaultValue !== undefined) {
        return { key: primaryKey, info: primaryInfo };
    }
    const secondaryInfo = safeInspect(inspectFn, secondaryKey);
    if (secondaryInfo && secondaryInfo.defaultValue !== undefined) {
        return { key: secondaryKey, info: secondaryInfo };
    }
    return { key: primaryKey, info: primaryInfo };
}

function resolveText(template, value) {
    return typeof template === 'function' ? template(value) : template;
}

/** Resolves one health check from `inspect()`, probing support via `defaultValue`. */
function readCheck(inspectFn, check, options = {}) {
    const { key, info } = resolveCheckKey(inspectFn, check, options);
    if (!info || info.defaultValue === undefined) {
        return {
            id: check.id, key, icon: check.icon, label: check.label,
            state: 'unavailable', value: undefined, valueLabel: 'Not available',
            recommended: check.recommended, recommendedLabel: check.format(check.recommended),
            sub: check.unavailableSub || 'Not available in this editor',
            detail: check.unavailableDetail || 'This editor does not have this setting.',
            tooltip: check.tooltip
        };
    }
    const value = info.globalValue !== undefined ? info.globalValue : info.defaultValue;
    const settingSafe = check.isSafe(value);
    // Warn on Auto-run tasks whenever there are unaddressed file threats in .vscode/ or the workspace.
    const fileThreatCount = check.id === 'automaticTasks' ? (Number(options && options.fileThreatCount) || 0) : 0;
    const state = settingSafe && fileThreatCount === 0 ? 'satisfied' : 'unsatisfied';
    let sub = resolveText(settingSafe ? check.safeSub : check.unsafeSub, value);
    let detail = resolveText(settingSafe ? check.safeDetail : check.unsafeDetail, value);
    if (fileThreatCount > 0) {
        const threatNoun = fileThreatCount === 1 ? '1 unaddressed file threat' : `${fileThreatCount} unaddressed file threats`;
        sub = settingSafe
            ? `Action needed · ${threatNoun} found`
            : `Action needed · Tasks can run when a folder opens (${threatNoun})`;
        detail = `${threatNoun} detected in .vscode or workspace. Quarantine or allow the threat in File threats to clear this warning.`;
    }
    return {
        id: check.id, key, icon: check.icon, label: check.label,
        state, value, valueLabel: check.format(value),
        recommended: check.recommended, recommendedLabel: check.format(check.recommended),
        sub,
        detail,
        tooltip: check.tooltip,
        fileThreatWarning: settingSafe && fileThreatCount > 0
    };
}

/** Resolves all five editor health checks. */
const readState = (inspectFn, options) => CHECKS.map(check => readCheck(inspectFn, check, options));
const openCount = rows => (Array.isArray(rows) ? rows : []).filter(r => r.state === 'unsatisfied').length;
const allSatisfied = rows => Array.isArray(rows) && rows.length > 0 && rows.every(r => r.state === 'satisfied');

/** Writes one setting at Global scope and catches any editor error. */
async function applySetting(updateFn, key, value) {
    if (typeof updateFn !== 'function' || !key) return { ok: false, applied: false, error: 'Settings are not writable in this editor.' };
    try { await updateFn(key, value); return { ok: true, applied: true }; }
    catch (error) { return { ok: false, applied: false, error: errorText(error) }; }
}

/** Applies the recommended value for a check only if it is currently `unsatisfied`. */
async function applyCheck(updateFn, inspectFn, checkId, options) {
    const row = readState(inspectFn, options).find(item => item.id === checkId);
    if (!row) return { ok: false, applied: false, error: 'Unknown check.' };
    if (row.state === 'unavailable') return { ok: false, applied: false, error: row.detail };
    if (row.state === 'satisfied') return { ok: true, applied: false, noop: true, row };
    return { ...(await applySetting(updateFn, row.key, row.recommended)), row };
}

/**
 * Builds a compact, privacy-safe summary of the user's editor security posture
 * for telemetry (`health_check_posture`). Used with `telemetry.recordState()`
 * so each user only sends their posture once initially and when a check or the
 * marketplace proxy toggle actually changes.
 */
function summarizeHealthPosture(rows, { proxyEnabled = true, editorVersion = '' } = {}) {
    const list = Array.isArray(rows) ? rows : [];
    const byId = Object.fromEntries(list.map(r => [r.id, r]));
    const delayRow = byId.autoUpdateDelay;
    const delayHours = !delayRow || delayRow.state === 'unavailable'
        ? -1
        : (Number.isFinite(Number(delayRow.value)) ? Number(delayRow.value) : 0);
    const proxyOn = proxyEnabled !== false;
    const unmetCount = openCount(list) + (proxyOn ? 0 : 1);

    return {
        unmet_count: unmetCount,
        all_safe: unmetCount === 0,
        proxy_enabled: proxyOn,
        automatic_tasks: (byId.automaticTasks && byId.automaticTasks.state) || 'unavailable',
        auto_update_delay: (delayRow && delayRow.state) || 'unavailable',
        auto_update_delay_hours: delayHours,
        trust_prompt: (byId.trustPrompt && byId.trustPrompt.state) || 'unavailable',
        ignore_recommendations: (byId.ignoreRecommendations && byId.ignoreRecommendations.state) || 'unavailable',
        workspace_trust: (byId.workspaceTrust && byId.workspaceTrust.state) || 'unavailable',
        editor_version: versionBucket(editorVersion)
    };
}

/** Warns the user on startup if any health check items (or the proxy) are not met. */
function notifyUnmetHealthChecks({ inspectFn, appName, editorVersion = '', proxyEnabled = true, proxyNeedsRestart = false, fileThreatCount = 0, showWarning, onOpenPane, telemetry } = {}) {
    const rows = readState(inspectFn, { appName, fileThreatCount });
    const posture = summarizeHealthPosture(rows, { proxyEnabled, editorVersion });
    // Report the user's health posture only when it changes (`recordState`).
    if (typeof telemetry?.recordState === 'function') {
        telemetry.recordState('health_posture', 'health_check_posture', posture);
    } else {
        telemetry?.record?.('health_check_posture', posture);
    }

    const unmet = rows.filter(r => r.state === 'unsatisfied').map(r => r.label);
    if (proxyEnabled === false) unmet.push('Marketplace proxy');
    else if (proxyNeedsRestart) unmet.push('Marketplace proxy (restart required)');
    if (unmet.length === 0) return 0;

    // Record that the startup warning was shown only when the unmet set changes,
    // so reloading windows does not repeatedly blast `health_check_warning_shown`.
    const warnProps = { unmet_count: unmet.length, proxy_enabled: proxyEnabled !== false };
    if (typeof telemetry?.recordState === 'function') {
        telemetry.recordState('health_warning_unmet', 'health_check_warning_shown', warnProps);
    } else {
        telemetry?.record?.('health_check_warning_shown', warnProps);
    }

    const noun = unmet.length === 1 ? '1 health check item is not met' : `${unmet.length} health check items are not met`;
    if (typeof showWarning === 'function') {
        Promise.resolve(showWarning(`dev-guard: ${noun} (${unmet.join(', ')}).`, 'Review Health Check')).then(sel => {
            if (sel === 'Review Health Check') {
                telemetry?.record?.('health_check_warning_action', { action: 'review', unmet_count: unmet.length });
                onOpenPane?.();
            } else if (typeof telemetry?.recordOnce === 'function') {
                telemetry.recordOnce('health_warning_dismissed', 'health_check_warning_action', { action: 'dismiss', unmet_count: unmet.length });
            } else {
                telemetry?.record?.('health_check_warning_action', { action: 'dismiss', unmet_count: unmet.length });
            }
        }).catch(() => {});
    }
    return unmet.length;
}

function versionBucket(version) {
    const match = /^(\d+)\.(\d+)/.exec(String(version || ''));
    if (!match) return 'unknown';
    const [major, minor] = [Number(match[1]), Number(match[2])];
    if (major > 1 || (major === 1 && minor >= 125)) return '1.125+';
    return major === 1 && minor >= 109 ? '1.109-1.124' : '<1.109';
}

module.exports = {
    CHECKS, AUTOMATIC_TASKS, AUTO_UPDATE_DELAY, CURSOR_COOLDOWN_KEY, TRUST_STARTUP_PROMPT,
    IGNORE_RECOMMENDATIONS, WORKSPACE_TRUST_ENABLED, splitSettingKey,
    readState, openCount, allSatisfied, applySetting, applyCheck,
    summarizeHealthPosture, notifyUnmetHealthChecks, versionBucket
};
