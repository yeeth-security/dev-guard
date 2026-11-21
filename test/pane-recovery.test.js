// The pane's "Allow and reinstall" action, driven through the real provider
// with a vscode stub. Covers the trust decision, the allowlist write, the
// install, and the failure path.

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

const settings = {};
const calls = [];
const state = { confirm: 'Allow and reinstall', installFails: false };
const captured = {};

const vscodeStub = {
    ConfigurationTarget: { Global: 1 },
    version: '1.145.1',
    env: { appName: 'Visual Studio Code' },
    window: {
        showWarningMessage: async () => state.confirm,
        showInformationMessage: async () => undefined,
        showErrorMessage: async message => { calls.push(['error', message]); },
        setStatusBarMessage: () => {},
        registerWebviewViewProvider: (_id, provider) => {
            captured.provider = provider;
            return { dispose() {} };
        }
    },
    workspace: {
        getConfiguration: () => ({
            get: (key, fallback) => (key in settings ? settings[key] : fallback),
            update: async (key, value) => { settings[key] = value; },
            inspect: () => undefined
        }),
        onDidChangeConfiguration: () => ({ dispose() {} })
    },
    commands: {
        executeCommand: async (...args) => {
            calls.push(args);
            if (args[0] === 'workbench.extensions.installExtension' && state.installFails) {
                throw new Error('gallery unavailable');
            }
        }
    },
    Uri: {}
};

const originalLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === 'vscode') return vscodeStub;
    return originalLoad.call(this, request, ...rest);
};
const { createPane } = require('../ui/pane');
Module._load = originalLoad;

function makePane(overrides = {}) {
    const recorded = [];
    const pane = createPane({
        history: { listRuns: () => [], onChange: () => () => {} },
        audit: { list: () => [], onChange: () => () => {}, record: entry => recorded.push(entry) },
        getStatus: () => ({}),
        runScan: async () => {},
        telemetry: { record: (...args) => calls.push(['telemetry', ...args]) },
        ...overrides
    });
    return { pane, recorded };
}

/** Resolves the view, then returns a `send` that waits for the async handler. */
function open(pane) {
    const view = {
        visible: true,
        webview: {
            options: {},
            html: '',
            onDidReceiveMessage(fn) { this.handler = fn; },
            postMessage: async () => {}
        },
        onDidChangeVisibility() {},
        onDidDispose() {}
    };
    captured.provider.resolveWebviewView(view);
    return async message => {
        view.webview.handler(message);
        await new Promise(resolve => setTimeout(resolve, 20));
    };
}

test('allow and reinstall writes the allowlist, installs, and clears the pending reload', async () => {
    settings.allowlist = [];
    calls.length = 0;
    state.confirm = 'Allow and reinstall';
    state.installFails = false;
    const restored = [];
    const { pane, recorded } = makePane({ onRestoreExtension: id => restored.push(id) });

    await open(pane)({ type: 'allowReinstall', id: 'Wrong.Ext' });

    assert.deepEqual(settings.allowlist, ['wrong.ext']);
    assert.deepEqual(recorded, [{ type: 'allowed', id: 'Wrong.Ext' }]);
    assert.ok(calls.some(c => c[0] === 'workbench.extensions.installExtension' && c[1] === 'Wrong.Ext'));
    assert.deepEqual(restored, ['Wrong.Ext']);
    assert.ok(calls.some(c => c[0] === 'telemetry' && c[1] === 'removal_recovered'));
    pane.dispose();
});

test('cancelling the confirmation changes nothing', async () => {
    settings.allowlist = [];
    calls.length = 0;
    state.confirm = undefined;
    const restored = [];
    const { pane, recorded } = makePane({ onRestoreExtension: id => restored.push(id) });

    await open(pane)({ type: 'allowReinstall', id: 'wrong.ext' });

    assert.deepEqual(settings.allowlist, [], 'no allowlist write');
    assert.deepEqual(recorded, []);
    assert.ok(!calls.some(c => c[0] === 'workbench.extensions.installExtension'));
    assert.deepEqual(restored, []);
    assert.ok(calls.some(c => c[0] === 'telemetry' && c[1] === 'allowlist_cancelled'));
    pane.dispose();
});

test('a failed install keeps the allowlist entry and says so', async () => {
    settings.allowlist = [];
    calls.length = 0;
    state.confirm = 'Allow and reinstall';
    state.installFails = true;
    const restored = [];
    const { pane } = makePane({ onRestoreExtension: id => restored.push(id) });

    await open(pane)({ type: 'allowReinstall', id: 'wrong.ext' });

    assert.deepEqual(settings.allowlist, ['wrong.ext'], 'a manual install must not be removed again');
    assert.deepEqual(restored, [], 'the removal still counts as pending');
    const error = calls.find(c => c[0] === 'error');
    assert.ok(error && /could not reinstall/.test(error[1]));
    assert.ok(calls.some(c => c[0] === 'telemetry' && c[1] === 'removal_recovery_failed'));
    state.installFails = false;
    pane.dispose();
});
