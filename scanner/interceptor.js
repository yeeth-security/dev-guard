/**
 * Active task interceptor and emergency auto-task shutoff (`scanner/interceptor.js`).
 *
 * Why this file exists:
 *   When `task.allowAutomaticTasks` is `on`, a trusted workspace can start a
 *   `runOn: "folderOpen"` task as soon as the folder opens. Multi-stage
 *   payloads like `vscode-bootstrap.sh` spend several seconds downloading a
 *   portable Node runtime and running `curl` + `npm install` before they run
 *   the second-stage `env-setup.js` payload.
 *
 *   This module catches those tasks mid-flight:
 *     1. Checks `vscode.tasks.taskExecutions` immediately at 0ms on activation
 *        and subscribes to `vscode.tasks.onDidStartTask`.
 *     2. Calls `execution.terminate()` on any task whose name matches a flagged
 *        task from `.vscode/tasks.json` or whose command line executes `.vscode/`
 *        scripts or remote downloaders.
 *     3. Automatically sets `task.allowAutomaticTasks` to `off` at Global scope
 *        whenever a malicious `folderOpen` task is found so it cannot re-run.
 */

const { checkShellBootstrapHeuristics } = require('./rules');

/** Extracts a printable command string from a VS Code Task's execution object. */
function extractTaskCommand(task) {
    if (!task || !task.execution) return '';
    const exec = task.execution;
    const cmd = typeof exec.commandLine === 'string'
        ? exec.commandLine
        : (typeof exec.command === 'string' ? exec.command : (exec.command && exec.command.value) || '');
    const args = Array.isArray(exec.args)
        ? exec.args.map(a => (typeof a === 'string' ? a : (a && a.value) || '')).join(' ')
        : '';
    return `${cmd} ${args}`.trim();
}

/**
 * Decides whether a running VS Code `TaskExecution` is malicious and should be
 * terminated immediately.
 * @param {any} execution VS Code `TaskExecution`
 * @param {Set<string>} flaggedTaskNames Lowercase task labels flagged by `scanner/workspace.js`
 */
function isMaliciousTaskExecution(execution, flaggedTaskNames = new Set()) {
    if (!execution || !execution.task) return false;
    const name = String(execution.task.name || '').trim().toLowerCase();
    if (name && flaggedTaskNames instanceof Set && flaggedTaskNames.has(name)) {
        return true;
    }
    const cmdText = extractTaskCommand(execution.task);
    if (!cmdText) return false;
    if (/\.vscode[/\\][^\s"']+\.(sh|bash|zsh|js|mjs|cjs|py|ps1|bat|cmd|vbs)\b/i.test(cmdText)) {
        return true;
    }
    return checkShellBootstrapHeuristics(cmdText).length > 0;
}

/**
 * Inspects all currently running `vscode.tasks.taskExecutions` and terminates
 * any that match a flagged `.vscode/tasks.json` entry or suspicious command.
 */
function terminateMaliciousTasks({ vscodeApi, findings = [], audit, telemetry } = {}) {
    const tasksApi = vscodeApi && vscodeApi.tasks;
    if (!tasksApi) return [];

    const flaggedNames = new Set();
    for (const f of Array.isArray(findings) ? findings : []) {
        for (const label of Array.isArray(f && f.flaggedTasks) ? f.flaggedTasks : []) {
            flaggedNames.add(String(label).trim().toLowerCase());
        }
    }

    const terminated = [];
    const active = Array.isArray(tasksApi.taskExecutions) ? tasksApi.taskExecutions : [];
    for (const execution of active) {
        if (!isMaliciousTaskExecution(execution, flaggedNames)) continue;
        try {
            if (typeof execution.terminate === 'function') {
                execution.terminate();
                const taskName = (execution.task && execution.task.name) || 'task';
                terminated.push(taskName);
                audit?.record({ type: 'terminated', detail: `Killed malicious task: ${taskName}` });
                telemetry?.record('task_terminated', { trigger: 'interceptor' });
            }
        } catch (_e) {
            // Ignore termination errors.
        }
    }
    return terminated;
}

/**
 * If a workspace contains a flagged `runOn: "folderOpen"` task and the user's
 * `task.allowAutomaticTasks` setting is currently `on`, flips it to `off` at
 * Global scope so the malicious task cannot run again on reload.
 */
async function disableAutoTasksIfThreatFound({ vscodeApi, findings = [], audit, telemetry } = {}) {
    const hasAutoOpenThreat = (Array.isArray(findings) ? findings : []).some(f => f && f.hasFolderOpenTask);
    if (!hasAutoOpenThreat || !vscodeApi || !vscodeApi.workspace) return false;

    try {
        const config = vscodeApi.workspace.getConfiguration('task');
        const info = typeof config.inspect === 'function' ? config.inspect('allowAutomaticTasks') : null;
        const current = info && info.globalValue !== undefined
            ? info.globalValue
            : (typeof config.get === 'function' ? config.get('allowAutomaticTasks') : 'off');
        if (String(current || '').toLowerCase() !== 'on') return false;

        const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
        await config.update('allowAutomaticTasks', 'off', target);
        audit?.record({ type: 'hardening', detail: 'task.allowAutomaticTasks (auto-disabled on threat)' });
        telemetry?.record('hardening_applied', { setting: 'task.allowAutomaticTasks', reason: 'folder_open_threat' });
        return true;
    } catch (_e) {
        return false;
    }
}

/**
 * Subscribes to `vscode.tasks.onDidStartTask` so any malicious task started
 * after activation is terminated the moment it spawns.
 */
function createTaskInterceptor({ vscodeApi, getFindings, onTerminated, audit, telemetry } = {}) {
    const tasksApi = vscodeApi && vscodeApi.tasks;
    if (!tasksApi || typeof tasksApi.onDidStartTask !== 'function') {
        return { dispose() {} };
    }
    const sub = tasksApi.onDidStartTask(event => {
        const execution = event && event.execution;
        const findings = typeof getFindings === 'function' ? getFindings() : [];
        const flaggedNames = new Set();
        for (const f of Array.isArray(findings) ? findings : []) {
            for (const label of Array.isArray(f && f.flaggedTasks) ? f.flaggedTasks : []) {
                flaggedNames.add(String(label).trim().toLowerCase());
            }
        }
        if (isMaliciousTaskExecution(execution, flaggedNames)) {
            try {
                execution.terminate();
                const taskName = (execution.task && execution.task.name) || 'task';
                audit?.record({ type: 'terminated', detail: `Killed malicious task: ${taskName}` });
                telemetry?.record('task_terminated', { trigger: 'onDidStartTask' });
                onTerminated?.(taskName);
            } catch (_e) { /* ignore */ }
        }
    });
    return sub;
}

module.exports = {
    extractTaskCommand,
    isMaliciousTaskExecution,
    terminateMaliciousTasks,
    disableAutoTasksIfThreatFound,
    createTaskInterceptor
};
