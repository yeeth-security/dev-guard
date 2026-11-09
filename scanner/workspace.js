/**
 * Workspace `.vscode/`, tasks, settings, `.git/hooks`, and npm config scanner
 * (`scanner/workspace.js`).
 *
 * Why this file exists:
 *   Malicious git repositories stage scripts and manifests inside `.vscode/`
 *   and trigger them using `.vscode/tasks.json` (`runOn: "folderOpen"`),
 *   `.vscode/launch.json`, `.vscode/settings.json` terminal/env overrides,
 *   `.git/hooks/`, or the npm config file. This module inspects opened
 *   workspace folders for all of these persistence and auto-execution vectors.
 *
 * Design:
 *   - Pure module with no `vscode` import so every check is unit-testable.
 *   - Strips comments and trailing commas (JSONC) before parsing VS Code JSON files.
 *   - Records flagged task labels and `hasFolderOpenTask` so the active task
 *     interceptor can terminate running malicious tasks immediately.
 *   - Signature literals come from `signatures.json` (see `rules.js`).
 */

const fs = require('fs');
const path = require('path');
const SIGNATURES = require('./signatures.json');
const { MAX_SCAN_BYTES, NPM_CONFIG_FILE, sha256Text, highestSeverity, scanFileContent } = require('./rules');
const { SCRIPT_EXT_RE, STAGED_MANIFEST_NAMES, PORTABLE_NODE_RE } = require('./profile');

/** Downloaders and script tokens that make a workspace task or hook suspicious. */
const SUSPICIOUS_SHELL_RE = new RegExp(
    `\\.vscode[/\\\\]|\\b(?:${SIGNATURES.shellDownloaders.join('|')}|eval|base64)\\b`,
    'i'
);
/** Git hooks: any `.vscode` reference counts, not just a path into it. */
const SUSPICIOUS_HOOK_RE = new RegExp(
    `\\.vscode|\\b(?:${SIGNATURES.shellDownloaders.join('|')}|eval|base64)\\b`,
    'i'
);

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
    let hasFolderOpenTask = false;

    for (const t of tasks) {
        if (!t || typeof t !== 'object') continue;
        const label = String(t.label || t.taskName || 'unnamed-task');
        const runOn = t.runOptions && String(t.runOptions.runOn || '').toLowerCase();
        const cmdText = [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter(Boolean).join(' ');
        const isAutoOpen = runOn === 'folderopen';
        const callsSuspicious = SUSPICIOUS_SHELL_RE.test(cmdText);

        if (isAutoOpen || callsSuspicious) {
            if (isAutoOpen) hasFolderOpenTask = true;
            flaggedTasks.push(label);
            matches.push({
                rule: isAutoOpen && callsSuspicious ? 'REMOTE_PAYLOAD' : 'C2_COMMUNICATION',
                technique: isAutoOpen && callsSuspicious ? 'T1105' : 'T1059',
                severity: isAutoOpen && callsSuspicious ? 'critical' : 'high',
                detail: isAutoOpen
                    ? `Task "${label}" runs automatically on folderOpen (${cmdText || 'shell command'}).`
                    : `Task "${label}" executes a script inside .vscode/ or downloads remote content.`
            });
        }
    }
    return { matches, flaggedTasks, hasFolderOpenTask };
}

/** Checks `.vscode/settings.json` for terminal env hijacks (`NODE_OPTIONS`, `.vscode` PATH) or tool overrides. */
function analyzeSettingsJson(text) {
    const parsed = parseJsonc(text);
    if (!parsed || typeof parsed !== 'object') return [];
    const matches = [];
    for (const [key, val] of Object.entries(parsed)) {
        const serialized = JSON.stringify(val || '');
        if (/^terminal\.integrated\.(env|profiles|automationProfile|shell)\b/.test(key)) {
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

/** Checks `.vscode/launch.json` for debug configurations that execute `.vscode/` scripts. */
function analyzeLaunchJson(text) {
    const parsed = parseJsonc(text);
    const configs = parsed && Array.isArray(parsed.configurations) ? parsed.configurations : [];
    const matches = [];
    for (const cfg of configs) {
        if (!cfg || typeof cfg !== 'object') continue;
        const fields = [cfg.program, cfg.runtimeExecutable, cfg.preLaunchTask, cfg.postDebugTask].filter(Boolean).join(' ');
        if (/\.vscode[/\\]/i.test(fields)) {
            matches.push({
                rule: 'C2_COMMUNICATION',
                technique: 'T1059',
                severity: 'high',
                detail: `Debug config "${cfg.name || 'launch'}" invokes a script or binary inside .vscode/.`
            });
        }
    }
    return matches;
}

/** Scans a single workspace folder for `.vscode/`, `.git/hooks/`, and npm config threats. */
function scanWorkspaceFolder(folderPath, io = {}) {
    const readdirSync = io.readdirSync || fs.readdirSync;
    const statSync = io.statSync || fs.statSync;
    const readFileSync = io.readFileSync || fs.readFileSync;
    const findings = [];
    const vscodeDir = path.join(folderPath, '.vscode');

    // 1. Inspect entries in <workspace>/.vscode/
    let vscodeEntries = [];
    try { vscodeEntries = readdirSync(vscodeDir); } catch (_e) { vscodeEntries = []; }
    for (const rawName of vscodeEntries) {
        const name = String(rawName || '');
        const lower = name.toLowerCase();
        const fullPath = path.join(vscodeDir, name);
        const relPath = `.vscode/${name}`;

        if (lower === 'tasks.json' || lower === 'settings.json' || lower === 'launch.json') {
            const text = readText(fullPath, readFileSync);
            if (!text) continue;
            const taskRes = lower === 'tasks.json' ? analyzeTasksJson(text) : null;
            const matches = taskRes ? taskRes.matches : (lower === 'settings.json' ? analyzeSettingsJson(text) : analyzeLaunchJson(text));
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

    // 2. Inspect <workspace>/npm-config for script-shell hijacks.
    const rootNpmrc = path.join(folderPath, NPM_CONFIG_FILE);
    const npmrcText = readText(rootNpmrc, readFileSync);
    if (npmrcText) {
        const matches = scanFileContent({ fileName: NPM_CONFIG_FILE, content: npmrcText, inVscodeDir: false });
        if (matches.length > 0) {
            findings.push({
                id: `workspace:${rootNpmrc}`, scope: 'workspace', filePath: rootNpmrc, displayPath: NPM_CONFIG_FILE,
                fileName: NPM_CONFIG_FILE, sha256: sha256Text(npmrcText), severity: highestSeverity(matches), matches
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
        if (matches.length === 0 && SUSPICIOUS_HOOK_RE.test(hookText)) {
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
