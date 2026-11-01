/**
 * "Harden this editor" checks (ENG-27).
 *
 * The Contagious Interview campaign ships a repository whose `.vscode/tasks.json`
 * runs a task when the folder opens. The editor is not defenceless — the safe
 * state is just spread across six settings, two of them new. This module knows
 * which settings matter, what the safe value is, and whether the editor on this
 * machine is already there.
 *
 * Pure module: no `vscode` import, so every rule here is unit tested. The pane
 * supplies the two `vscode` calls:
 *   - `inspectFn(key)`  -> `workspace.getConfiguration(section).inspect(name)`
 *   - `updateFn(key, value)` -> `configuration.update(key, value, Global)`
 *
 * Hard rules (ENG-27):
 *   - State comes from `inspect()`, never `get()`. The global value (or the
 *     editor default) is reported; a workspace-scoped value is never shown or
 *     mistaken for the user's own choice.
 *   - Support is probed with `defaultValue !== undefined`. An unregistered
 *     setting returns `undefined`, which is how the cooldown row knows the
 *     editor predates VS Code 1.125.
 *   - Apply only when the check is unsatisfied, and never throw into the pane.
 *   - One click changes one setting. There is no "apply all".
 */

/** Recommended values. Keep in sync with CHECKS below and the ticket table. */
const AUTOMATIC_TASKS = 'off';
const AUTO_UPDATE_DELAY = 24;
const TRUST_STARTUP_PROMPT = 'always';
const IGNORE_RECOMMENDATIONS = true;
const WORKSPACE_TRUST_ENABLED = true;

const COOLDOWN_TOOLTIP =
    'Applies to auto-updates of enabled extensions only. Trusted publishers (Microsoft, GitHub, OpenAI) ' +
    'are not delayed, first-time installs are not delayed, and this does nothing while auto-update is off.';

/** One row per check. `isSafe` decides the state; `format` is what the row shows. */
const CHECKS = Object.freeze([
    {
        id: 'automaticTasks',
        key: 'task.allowAutomaticTasks',
        label: 'Auto-run tasks',
        recommended: AUTOMATIC_TASKS,
        isSafe: value => String(value).toLowerCase() === AUTOMATIC_TASKS,
        isOn: value => String(value).toLowerCase() === 'on',
        format: value => (String(value).toLowerCase() === 'on' ? 'On' : 'Off'),
        safeDetail: 'Tasks in a folder cannot run just because the folder opened.',
        unsafeDetail: 'A task in .vscode/tasks.json can run as soon as the folder opens.',
        tooltip: 'VS Code 1.109+ defaults to off; anyone who turned it on earlier keeps it on.'
    },
    {
        id: 'autoUpdateDelay',
        key: 'extensions.autoUpdateDelay',
        label: 'Delay auto-updates',
        recommended: AUTO_UPDATE_DELAY,
        isSafe: value => Number(value) >= AUTO_UPDATE_DELAY,
        isOn: value => Number(value) > 0,
        format: value => (Number(value) > 0 ? `${Number(value)} h` : 'Off'),
        safeDetail: 'Extension updates wait before they install, leaving a window to pull a bad one.',
        unsafeDetail: 'Extension updates install right away, with no window to pull a bad one.',
        unavailableDetail: 'Needs VS Code 1.125+ (or a fork that ships it).',
        tooltip: COOLDOWN_TOOLTIP
    },
    {
        id: 'trustPrompt',
        key: 'security.workspace.trust.startupPrompt',
        label: 'Ask before trust',
        recommended: TRUST_STARTUP_PROMPT,
        isSafe: value => String(value).toLowerCase() === TRUST_STARTUP_PROMPT,
        isOn: value => String(value).toLowerCase() === TRUST_STARTUP_PROMPT,
        format: value => {
            const text = String(value || '').toLowerCase();
            return text ? text.charAt(0).toUpperCase() + text.slice(1) : 'Unknown';
        },
        safeDetail: 'Opening a folder always asks before it is trusted.',
        unsafeDetail: 'A folder can be trusted without the editor asking first.',
        tooltip: 'Trust becomes a decision instead of a default.'
    },
    {
        id: 'ignoreRecommendations',
        key: 'extensions.ignoreRecommendations',
        label: 'Hide suggestions',
        recommended: IGNORE_RECOMMENDATIONS,
        isSafe: value => value === true,
        isOn: value => value === true,
        format: value => (value === true ? 'Hidden' : 'Shown'),
        safeDetail: 'A repository cannot nudge you to install the extensions it lists.',
        unsafeDetail: '.vscode/extensions.json can nudge you to install the extensions it lists.',
        tooltip: 'Stops a repository from recommending its own extensions.'
    },
    {
        id: 'workspaceTrust',
        key: 'security.workspace.trust.enabled',
        label: 'Workspace Trust',
        recommended: WORKSPACE_TRUST_ENABLED,
        isSafe: value => value === true,
        isOn: value => value === true,
        format: value => (value === true ? 'On' : 'Off'),
        safeDetail: 'Restricted Mode is available to block terminals, tasks, and debugging.',
        unsafeDetail: 'Restricted Mode is off, so an unknown folder is never sandboxed.',
        tooltip: 'This is the base switch for everything else in this section.'
    }
]);

/** Settings are written with `ConfigurationTarget.Global` by the caller. */
function splitSettingKey(key) {
    const text = String(key || '');
    const dot = text.lastIndexOf('.');
    return dot > 0
        ? { section: text.slice(0, dot), name: text.slice(dot + 1) }
        : { section: undefined, name: text };
}

function safeInspect(inspectFn, key) {
    if (typeof inspectFn !== 'function') return undefined;
    try {
        return inspectFn(key) || undefined;
    } catch (_error) {
        return undefined; // A fork that throws for unknown settings still renders.
    }
}

/** Short, safe text for an error the editor threw while writing a setting. */
function errorText(error) {
    const message = error && (error.message || error)
        ? String(error.message || error).trim()
        : '';
    return (message || 'The editor rejected this change.').slice(0, 200);
}

/**
 * Resolves one check against the editor's settings.
 * @returns {{id: string, key: string, label: string, state: 'satisfied'|'unsatisfied'|'unavailable',
 *   value: unknown, valueLabel: string, recommended: unknown, recommendedLabel: string,
 *   detail: string, tooltip: string}}
 */
function readCheck(inspectFn, check) {
    const info = safeInspect(inspectFn, check.key);
    // Unregistered settings have no defaultValue. This is the support probe.
    if (!info || info.defaultValue === undefined) {
        return {
            id: check.id,
            key: check.key,
            label: check.label,
            state: 'unavailable',
            value: undefined,
            valueLabel: 'Not available',
            on: false,
            recommended: check.recommended,
            recommendedLabel: check.format(check.recommended),
            detail: check.unavailableDetail || 'This editor does not have this setting.',
            tooltip: check.tooltip
        };
    }

    // Global value wins. Workspace values are deliberately ignored: the row is
    // about what this user chose, and Apply only ever writes user settings.
    const value = info.globalValue !== undefined ? info.globalValue : info.defaultValue;
    const state = check.isSafe(value) ? 'satisfied' : 'unsatisfied';
    return {
        id: check.id,
        key: check.key,
        label: check.label,
        state,
        value,
        valueLabel: check.format(value),
        on: check.isOn(value),
        recommended: check.recommended,
        recommendedLabel: check.format(check.recommended),
        detail: state === 'satisfied' ? check.safeDetail : check.unsafeDetail,
        tooltip: check.tooltip
    };
}

/**
 * Resolves every check. `inspectFn` may throw or be missing; nothing here
 * throws into the pane.
 */
function readState(inspectFn) {
    return CHECKS.map(check => readCheck(inspectFn, check));
}

/** How many checks would still need an Apply. */
function openCount(rows) {
    return (Array.isArray(rows) ? rows : []).filter(row => row.state === 'unsatisfied').length;
}

/** True when every row is already safe. Unknown states never count as safe. */
function allSatisfied(rows) {
    const list = Array.isArray(rows) ? rows : [];
    return list.length > 0 && list.every(row => row.state === 'satisfied');
}

/**
 * Writes one setting at user (Global) scope. `updateFn(key, value)` must bind
 * `ConfigurationTarget.Global`; this module never writes workspace settings.
 * Returns a result instead of throwing, so a policy-managed or unsupported
 * setting becomes a message in the row.
 */
async function applySetting(updateFn, key, value) {
    if (typeof updateFn !== 'function' || !key) {
        return { ok: false, applied: false, error: 'Settings are not writable in this editor.' };
    }
    try {
        await updateFn(key, value);
        return { ok: true, applied: true };
    } catch (error) {
        return { ok: false, applied: false, error: errorText(error) };
    }
}

/**
 * The click path. Reads live state first and writes nothing when the check is
 * already safe or unavailable. This is the "already safe -> no write" rule.
 * @returns {Promise<{ok: boolean, applied: boolean, error?: string, row?: any, noop?: boolean}>}
 */
async function applyCheck(updateFn, inspectFn, checkId) {
    const row = readState(inspectFn).find(item => item.id === checkId);
    if (!row) return { ok: false, applied: false, error: 'Unknown check.' };
    if (row.state === 'unavailable') return { ok: false, applied: false, error: row.detail };
    if (row.state === 'satisfied') return { ok: true, applied: false, noop: true, row };

    const result = await applySetting(updateFn, row.key, row.recommended);
    return { ...result, row };
}

/**
 * Coarse editor version for telemetry. Enough to tell whether the update
 * cooldown could exist on this machine, without sending the exact version.
 */
function versionBucket(version) {
    const match = /^(\d+)\.(\d+)/.exec(String(version || ''));
    if (!match) return 'unknown';
    const major = Number(match[1]);
    const minor = Number(match[2]);
    if (major > 1 || (major === 1 && minor >= 125)) return '1.125+';
    if (major === 1 && minor >= 109) return '1.109-1.124';
    return '<1.109';
}

module.exports = {
    CHECKS,
    AUTOMATIC_TASKS,
    AUTO_UPDATE_DELAY,
    TRUST_STARTUP_PROMPT,
    IGNORE_RECOMMENDATIONS,
    WORKSPACE_TRUST_ENABLED,
    splitSettingKey,
    readState,
    openCount,
    allSatisfied,
    applySetting,
    applyCheck,
    versionBucket
};
