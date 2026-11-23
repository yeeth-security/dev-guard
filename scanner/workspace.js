/**
 * Workspace `.vscode/`, tasks, settings, `.git/hooks`, and `.npmrc` scanner (`scanner/workspace.js`).
 *
 * Why this file exists:
 *   Malicious git repositories stage scripts and manifests inside `.vscode/`
 *   and trigger them using `.vscode/tasks.json` (`runOn: "folderOpen"`),
 *   `.vscode/launch.json`, `.vscode/settings.json` terminal/env overrides,
 *   `.git/hooks/`, or `.npmrc`. This module inspects opened workspace folders
 *   for all of these persistence and auto-execution vectors.
 *
 * Design:
 *   - Pure module with no `vscode` import so every check is unit-testable.
 *   - Strips comments and trailing commas (JSONC) before parsing VS Code JSON files.
 *   - Records flagged task labels and `hasFolderOpenTask` so the active task
 *     interceptor can terminate running malicious tasks immediately.
 */

const fs = require('fs');
const path = require('path');
const { MAX_SCAN_BYTES, sha256Text, highestSeverity, scanFileContent } = require('./rules');
const { SCRIPT_EXT_RE, STAGED_MANIFEST_NAMES, PORTABLE_NODE_RE } = require('./profile');

/** Strips `//` and `/* *\/` comments and trailing commas so JSONC files parse cleanly. */
function parseJsonc(text) {
    try {
        const noComments = String(text || '')
            .replace(/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/gm, '$1')
            .replace(/,\s*([}\]])/g, '$1');
        return JSON.parse(noComments);
    } catch (_e) {
        return null;
    }
}

function readText(filePath, readFileSync = fs.readFileSync) {
    try {
        return String(readFileSync(filePath, 'utf8') || '').slice(0, MAX_SCAN_BYTES);
    } catch (_e) {
        return null;
    }
}

/** Checks `.vscode/tasks.json` for `runOn: "folderOpen"` and suspicious commands. */
function analyzeTasksJson(text) {
    const parsed = parseJsonc(text);
    const tasks = parsed && Array.isArray(parsed.tasks) ? parsed.tasks : [];
    const matches = [];
    const flaggedTasks = [];
    const flaggedTaskMatches = {};
    let hasFolderOpenTask = false;

    for (const t of tasks) {
        if (!t || typeof t !== 'object') continue;
        const label = String(t.label || t.taskName || 'unnamed-task');
        const runOn = t.runOptions && String(t.runOptions.runOn || '').toLowerCase();
        const cmdText = [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter(Boolean).join(' ');
        const isAutoOpen = runOn === 'folderopen';
        const callsSuspicious = /\.vscode[/\\]|\b(curl|wget|Invoke-WebRequest|iwr|eval|base64)\b/i.test(cmdText);

        if (isAutoOpen || callsSuspicious) {
            if (isAutoOpen) hasFolderOpenTask = true;
            flaggedTasks.push(label);
            const match = {
                rule: isAutoOpen && callsSuspicious ? 'REMOTE_PAYLOAD' : 'C2_COMMUNICATION',
                technique: isAutoOpen && callsSuspicious ? 'T1105' : 'T1059',
                severity: isAutoOpen && callsSuspicious ? 'critical' : 'high',
                detail: isAutoOpen
                    ? `Task "${label}" runs automatically on folderOpen (${cmdText || 'shell command'}).`
                    : `Task "${label}" executes a script inside .vscode/ or downloads remote content.`
            };
            matches.push(match);
            flaggedTaskMatches[label] = match;
        }
    }
    return { matches, flaggedTasks, flaggedTaskMatches, hasFolderOpenTask };
}

/** Checks `.vscode/settings.json` for terminal env hijacks (`NODE_OPTIONS`, `.vscode` PATH), tool overrides, or the automatic-task bypass. */
function analyzeSettingsJson(text, context = {}) {
    const parsed = parseJsonc(text);
    if (!parsed || typeof parsed !== 'object') return [];
    const matches = [];
    const hasFolderOpenTask = Boolean(context.hasFolderOpenTask);
    for (const [key, val] of Object.entries(parsed)) {
        const serialized = JSON.stringify(val || '');
        if (key === 'task.allowAutomaticTasks') {
            // "on" is the current opt-in and `true` is the legacy boolean form.
            // "off", "auto", and a missing key keep the prompt and stay quiet.
            if (val === true || String(val).toLowerCase() === 'on') {
                matches.push({
                    rule: 'C2_COMMUNICATION',
                    technique: 'T1059',
                    severity: hasFolderOpenTask ? 'critical' : 'high',
                    detail: `Workspace setting "task.allowAutomaticTasks" is ${JSON.stringify(val)}, which removes the automatic-task prompt.${hasFolderOpenTask ? ' A folder-open task in this workspace runs without confirmation.' : ''}`
                });
            }
        } else if (/^terminal\.integrated\.(env|profiles|automationProfile|shell)\b/.test(key)) {
            if (/NODE_OPTIONS|\.vscode|\b(curl|wget|bash|sh|node)\b/i.test(serialized)) {
                matches.push({
                    rule: 'C2_COMMUNICATION',
                    technique: 'T1059',
                    severity: 'high',
                    detail: `Workspace setting "${key}" overrides terminal environment or shell execution.`
                });
            }
        } else if (/\.(nodePath|tsdk|defaultInterpreterPath)$/.test(key) && /\.vscode/i.test(serialized)) {
            matches.push({
                rule: 'C2_COMMUNICATION',
                technique: 'T1059',
                severity: 'high',
                detail: `Workspace setting "${key}" points editor runtime to a binary inside .vscode/.`
            });
        }
    }
    return matches;
}

/** Checks `.vscode/launch.json` for debug configurations that execute `.vscode/` scripts or start flagged tasks. */
function analyzeLaunchJson(text, context = {}) {
    const parsed = parseJsonc(text);
    const configs = parsed && Array.isArray(parsed.configurations) ? parsed.configurations : [];
    const taskMatches = context.taskMatches && typeof context.taskMatches === 'object' ? context.taskMatches : {};
    const matches = [];
    for (const cfg of configs) {
        if (!cfg || typeof cfg !== 'object') continue;
        const fields = [cfg.program, cfg.runtimeExecutable, cfg.preLaunchTask, cfg.postDebugTask].filter(Boolean).join(' ');
        const pathFlagged = /\.vscode[/\\]/i.test(fields);
        if (pathFlagged) {
            matches.push({
                rule: 'C2_COMMUNICATION',
                technique: 'T1059',
                severity: 'high',
                detail: `Debug config "${cfg.name || 'launch'}" invokes a script or binary inside .vscode/.`
            });
        }

        // A bare label is only a real chain when it resolves to a task the
        // workspace tasks scan already flags. Unresolved labels stay quiet:
        // repositories routinely name tasks the user defines themselves.
        for (const field of ['preLaunchTask', 'postDebugTask']) {
            const label = cfg[field];
            if (typeof label !== 'string' || !label) continue;
            if (!Object.prototype.hasOwnProperty.call(taskMatches, label)) continue;
            if (pathFlagged && /\.vscode[/\\]/i.test(label)) continue;
            const task = taskMatches[label];
            matches.push({
                rule: task.rule || 'C2_COMMUNICATION',
                technique: task.technique || 'T1059',
                severity: task.severity || 'high',
                detail: `Debug config "${cfg.name || 'launch'}" starts ${field} "${label}", a task the workspace scan already flags.`
            });
        }
    }
    return matches;
}

/** Scans a single workspace folder for `.vscode/`, `.git/hooks/`, and `.npmrc` threats. */
function scanWorkspaceFolder(folderPath, io = {}) {
    const readdirSync = io.readdirSync || fs.readdirSync;
    const statSync = io.statSync || fs.statSync;
    const readFileSync = io.readFileSync || fs.readFileSync;
    const findings = [];
    const vscodeDir = path.join(folderPath, '.vscode');

    // 1. Inspect entries in <workspace>/.vscode/
    let vscodeEntries = [];
    try { vscodeEntries = readdirSync(vscodeDir); } catch (_e) { vscodeEntries = []; }

    // Read tasks.json first so settings.json and launch.json can share one
    // workspace-level view, regardless of directory iteration order.
    const tasksEntry = vscodeEntries.find(entry => String(entry || '').toLowerCase() === 'tasks.json');
    const tasksText = tasksEntry ? readText(path.join(vscodeDir, String(tasksEntry)), readFileSync) : null;
    const workspaceTasks = tasksText
        ? analyzeTasksJson(tasksText)
        : { matches: [], flaggedTasks: [], flaggedTaskMatches: {}, hasFolderOpenTask: false };

    for (const rawName of vscodeEntries) {
        const name = String(rawName || '');
        const lower = name.toLowerCase();
        const fullPath = path.join(vscodeDir, name);
        const relPath = `.vscode/${name}`;

        if (lower === 'tasks.json' || lower === 'settings.json' || lower === 'launch.json') {
            const text = readText(fullPath, readFileSync);
            if (!text) continue;
            const taskRes = lower === 'tasks.json' ? workspaceTasks : null;
            const matches = taskRes
                ? taskRes.matches
                : (lower === 'settings.json'
                    ? analyzeSettingsJson(text, { hasFolderOpenTask: workspaceTasks.hasFolderOpenTask })
                    : analyzeLaunchJson(text, { taskMatches: workspaceTasks.flaggedTaskMatches }));
            if (matches.length > 0) {
                findings.push({
                    id: `workspace:${fullPath}`, scope: 'workspace', filePath: fullPath, displayPath: relPath,
                    fileName: name, sha256: sha256Text(text), severity: highestSeverity(matches), matches,
                    flaggedTasks: taskRes ? taskRes.flaggedTasks : [],
                    hasFolderOpenTask: Boolean(taskRes && taskRes.hasFolderOpenTask)
                });
            }
            continue;
        }

        const isScript = SCRIPT_EXT_RE.test(lower);
        const isManifest = STAGED_MANIFEST_NAMES.has(lower);
        const isPortableNode = PORTABLE_NODE_RE.test(lower);
        if (!isScript && !isManifest && !isPortableNode) continue;

        let isDirectory = false;
        try { isDirectory = Boolean(statSync(fullPath).isDirectory()); } catch (_e) { isDirectory = lower === 'node_modules'; }
        const text = isDirectory ? '' : (readText(fullPath, readFileSync) || '');
        const matches = isDirectory ? [] : scanFileContent({ fileName: name, content: text, inVscodeDir: true });
        if (matches.length === 0) {
            matches.push({
                rule: isManifest ? 'ENV_HARVESTING' : 'REMOTE_PAYLOAD',
                technique: isManifest ? 'T1552.001' : 'T1105',
                severity: isScript || isPortableNode ? 'high' : 'medium',
                detail: `Unexpected ${isDirectory ? 'directory' : 'file'} (${relPath}) staged inside workspace .vscode/.`
            });
        }
        findings.push({
            id: `workspace:${fullPath}`, scope: 'workspace', filePath: fullPath, displayPath: relPath,
            fileName: name, sha256: isDirectory ? sha256Text(`dir:${fullPath}`) : sha256Text(text),
            severity: highestSeverity(matches), matches, isDirectory
        });
    }

    // 2. Inspect <workspace>/.npmrc for script-shell hijacks.
    const rootNpmrc = path.join(folderPath, '.npmrc');
    const npmrcText = readText(rootNpmrc, readFileSync);
    if (npmrcText) {
        const matches = scanFileContent({ fileName: '.npmrc', content: npmrcText, inVscodeDir: false });
        if (matches.length > 0) {
            findings.push({
                id: `workspace:${rootNpmrc}`, scope: 'workspace', filePath: rootNpmrc, displayPath: '.npmrc',
                fileName: '.npmrc', sha256: sha256Text(npmrcText), severity: highestSeverity(matches), matches
            });
        }
    }

    // 3. Inspect active <workspace>/.git/hooks/* (ignoring *.sample).
    const hooksDir = path.join(folderPath, '.git', 'hooks');
    let hooks = [];
    try { hooks = readdirSync(hooksDir); } catch (_e) { hooks = []; }
    for (const rawHook of hooks) {
        const hookName = String(rawHook || '');
        if (!hookName || hookName.toLowerCase().endsWith('.sample')) continue;
        const hookPath = path.join(hooksDir, hookName);
        const hookText = readText(hookPath, readFileSync);
        if (!hookText) continue;
        const matches = scanFileContent({ fileName: hookName, content: hookText, inVscodeDir: false });
        if (matches.length === 0 && /\.vscode|\b(curl|wget|Invoke-WebRequest|eval|base64)\b/i.test(hookText)) {
            matches.push({
                rule: 'REMOTE_PAYLOAD', technique: 'T1105', severity: 'high',
                detail: `Active Git hook (.git/hooks/${hookName}) invokes remote downloaders or .vscode scripts.`
            });
        }
        if (matches.length > 0) {
            findings.push({
                id: `workspace:${hookPath}`, scope: 'workspace', filePath: hookPath, displayPath: `.git/hooks/${hookName}`,
                fileName: hookName, sha256: sha256Text(hookText), severity: highestSeverity(matches), matches
            });
        }
    }

    return findings;
}

module.exports = { parseJsonc, analyzeTasksJson, analyzeSettingsJson, analyzeLaunchJson, scanWorkspaceFolder };
