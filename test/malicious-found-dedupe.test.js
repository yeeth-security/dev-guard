// Tests that `malicious_found` telemetry is sent once per extension + version,
// even when the same finding stays live across many audit cycles.
// Run with: npm test
//
// extension.js needs the 'vscode' module and the network, so we stub both:
//   - 'vscode' is a tiny fake (warn mode, no extensions of its own).
//   - './advisories/sync' returns a fixed advisory list instead of fetching.
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const os = require('os');

const ADVISORIES = [
    { extensionId: 'evil.one', version: '*', severity: 'high', registry: null },
    { extensionId: 'evil.two', version: '*', severity: 'critical', registry: null }
];

const fakeVscode = {
    extensions: { all: [] },
    workspace: {
        // Warn mode: the notifier only shows a toast. Nothing is uninstalled.
        getConfiguration: () => ({ get: (key, fallback) => (key === 'removalMode' ? 'warn' : fallback) })
    },
    // Leave the toast open. Resolving with no choice would show it again.
    window: { showErrorMessage: () => new Promise(() => {}), showInformationMessage: () => Promise.resolve(undefined) },
    env: { appRoot: os.tmpdir(), appName: 'Test', uriScheme: 'test' },
    commands: {},
    Uri: {}
};

// Stub 'vscode' and the network sync only while extension.js loads.
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === 'vscode') return fakeVscode;
    if (request === './advisories/sync') {
        return {
            mergeAdvisories: (a, b) => [...a, ...b],
            fetchPkgscanAdvisories: async () => ({ entries: ADVISORIES, rawItems: [], etag: null, minWaitMs: 0 })
        };
    }
    return originalLoad.call(this, request, ...rest);
};
const { checkAndReportMaliciousExtensions } = require('../extension');
Module._load = originalLoad;

// A fake installed extension. `extensionPath` is omitted, so it counts as "still installed".
const ext = (id, version) => ({ id, packageJSON: { version } });

// Runs one audit cycle and returns the `malicious_found` events it recorded.
async function runCycle(installed, context, trigger = 'poll') {
    const events = [];
    const telemetry = { record: (name, props) => events.push({ name, props }), flush: async () => {} };
    const outputChannel = { show() {}, appendLine() {} };
    fakeVscode.extensions.all = installed;
    await checkAndReportMaliciousExtensions(context, telemetry, outputChannel, trigger);
    return events.filter(e => e.name === 'malicious_found');
}

// Fresh fake context per test. Cache files go to the temp dir.
function fakeContext() {
    const store = new Map();
    return {
        extensionPath: os.tmpdir(),
        globalState: {
            get: key => store.get(key),
            update: (key, value) => { store.set(key, value); return Promise.resolve(); }
        }
    };
}

test('same finding across two audit cycles is reported once', async () => {
    const context = fakeContext();
    const first = await runCycle([ext('evil.one', '1.0.0')], context);
    const second = await runCycle([ext('evil.one', '1.0.0')], context);
    assert.equal(first.length, 1);
    assert.equal(second.length, 0, 'repeat cycle must not re-send telemetry');
});

test('a new version of the same extension is reported again', async () => {
    const context = fakeContext();
    // Use a unique id so earlier tests do not affect this one.
    await runCycle([ext('evil.one', '2.0.0')], context);
    const bumped = await runCycle([ext('evil.one', '2.0.1')], context);
    assert.equal(bumped.length, 1);
    assert.equal(bumped[0].props.installed_version, '2.0.1');
});

test('a different flagged extension is reported separately', async () => {
    const context = fakeContext();
    await runCycle([ext('evil.one', '3.0.0')], context);
    // evil.one is already reported; evil.two is new, so only it is sent.
    const events = await runCycle([ext('evil.one', '3.0.0'), ext('evil.two', '1.0.0')], context);
    assert.deepEqual(events.map(e => e.props.extension_id), ['evil.two']);
});

test('extension id casing does not create a second key', async () => {
    const context = fakeContext();
    await runCycle([ext('Evil.One', '4.0.0')], context);
    const again = await runCycle([ext('evil.one', '4.0.0')], context);
    assert.equal(again.length, 0);
});
