/**
 * Local file & profile threat scanner orchestrator (`scanner/index.js`).
 *
 * Why this file exists:
 *   Provides a single entry point for scanning both the user's global
 *   `~/.vscode/` profile directory and all opened workspace folders, filtering
 *   out allowlisted SHA-256 hashes, killing malicious running tasks, and
 *   watching `.vscode/`, `.git/hooks/`, and the npm config file for changes.
 */

const { SEVERITY_ORDER, NPM_CONFIG_FILE } = require('./rules');
const { scanProfileDirs } = require('./profile');
const { scanWorkspaceFolder } = require('./workspace');
const {
    formatAllowedFileEntry,
    normalizeAllowedFiles,
    readAllowedFiles,
    readAllowedFileRecords,
    allowFileHash,
    unallowFileHash,
    filterActiveFileFindings,
    listQuarantined,
    quarantineFinding,
    restoreQuarantinedFile,
    inspectFinding
} = require('./quarantine');
const {
    terminateMaliciousTasks,
    disableAutoTasksIfThreatFound,
    createTaskInterceptor
} = require('./interceptor');

/** Resolves filesystem paths of all currently open workspace folders. */
function resolveWorkspaceFolderPaths(vscodeApi, explicitFolders) {
    if (Array.isArray(explicitFolders)) return explicitFolders;
    const raw = (vscodeApi && vscodeApi.workspace && vscodeApi.workspace.workspaceFolders) || [];
    const paths = [];
    for (const folder of raw) {
        const fsPath = folder && (typeof folder === 'string' ? folder : folder.uri && folder.uri.fsPath);
        if (fsPath) paths.push(fsPath);
    }
    return paths;
}

/**
 * Runs both the user-profile (`~/.vscode`) scan and the workspace folder scan,
 * filters out SHA-256 allowlisted files, and sorts findings by severity.
 */
function runLocalFileScan(options = {}) {
    const vscodeApi = options.vscodeApi;
    const extensions = options.extensions || (vscodeApi && vscodeApi.extensions && vscodeApi.extensions.all) || [];
    const profileFindings = scanProfileDirs({
        extensions,
        homedir: options.homedir,
        profileDirs: options.profileDirs,
        io: options.io
    });

    const folderPaths = resolveWorkspaceFolderPaths(vscodeApi, options.workspaceFolders);
    const workspaceFindings = [];
    for (const folderPath of folderPaths) {
        workspaceFindings.push(...scanWorkspaceFolder(folderPath, options.io));
    }

    const allowedHashes = options.allowedHashes || (vscodeApi ? readAllowedFiles(vscodeApi) : new Set());
    const active = filterActiveFileFindings(
        [...profileFindings, ...workspaceFindings],
        allowedHashes,
        options.io
    );

    active.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));
    return active;
}

/**
 * Watches `.vscode/**`, `.git/hooks/**`, the npm config file, and workspace folder additions
 * so newly dropped payloads are scanned immediately.
 */
function createWorkspaceWatchers({ vscodeApi, onTrigger } = {}) {
    if (!vscodeApi || !vscodeApi.workspace) return { dispose() {} };
    const disposables = [];
    let debounceTimer = null;

    const schedule = () => {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            debounceTimer = null;
            onTrigger?.();
        }, 300);
        if (typeof debounceTimer?.unref === 'function') debounceTimer.unref();
    };

    if (typeof vscodeApi.workspace.createFileSystemWatcher === 'function') {
        for (const glob of ['**/.vscode/**', '**/.git/hooks/**', `**/${NPM_CONFIG_FILE}`]) {
            try {
                const watcher = vscodeApi.workspace.createFileSystemWatcher(glob);
                if (watcher.onDidCreate) disposables.push(watcher.onDidCreate(schedule));
                if (watcher.onDidChange) disposables.push(watcher.onDidChange(schedule));
                if (watcher.onDidDelete) disposables.push(watcher.onDidDelete(schedule));
                disposables.push(watcher);
            } catch (_e) { /* ignore watcher errors in unsupported hosts */ }
        }
    }

    if (typeof vscodeApi.workspace.onDidChangeWorkspaceFolders === 'function') {
        disposables.push(vscodeApi.workspace.onDidChangeWorkspaceFolders(schedule));
    }

    return {
        dispose() {
            if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
            while (disposables.length > 0) {
                const d = disposables.pop();
                try { d?.dispose?.(); } catch (_e) { /* ignore */ }
            }
        }
    };
}

module.exports = {
    runLocalFileScan,
    createWorkspaceWatchers,
    formatAllowedFileEntry,
    normalizeAllowedFiles,
    readAllowedFiles,
    readAllowedFileRecords,
    allowFileHash,
    unallowFileHash,
    filterActiveFileFindings,
    listQuarantined,
    quarantineFinding,
    restoreQuarantinedFile,
    inspectFinding,
    terminateMaliciousTasks,
    disableAutoTasksIfThreatFound,
    createTaskInterceptor
};
