// Tests for hardening.js (ENG-27) and the pane wiring around it.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

const {
    CHECKS, readState, openCount, allSatisfied, applySetting, applyCheck,
    splitSettingKey, versionBucket
} = require('../hardening');
const { renderHarden } = require('../ui/paneSections');
const { renderParts } = require('../ui/paneHtml');

/** Safe defaults for a modern editor (all five checks satisfied unless overridden). */
function safeSettings(overrides = {}) {
    return {
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'off' },
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 24 },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'always' },
        'extensions.ignoreRecommendations': { defaultValue: false, globalValue: true },
        'security.workspace.trust.enabled': { defaultValue: true, globalValue: true },
        ...overrides
    };
}

const inspectOf = (settings) => key => settings[key];

test('readState resolves satisfied, unsatisfied, and unavailable checks', () => {
    const settings = safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.autoUpdateDelay': undefined // unregistered setting
    });
    const rows = readState(inspectOf(settings));
    const byId = Object.fromEntries(rows.map(r => [r.id, r]));

    assert.equal(rows.length, 5);
    assert.equal(byId.automaticTasks.state, 'unsatisfied');
    assert.equal(byId.automaticTasks.valueLabel, 'On');
    assert.equal(byId.trustPrompt.state, 'unsatisfied');
    assert.equal(byId.trustPrompt.valueLabel, 'Once');
    assert.equal(byId.ignoreRecommendations.state, 'satisfied');
    assert.equal(byId.workspaceTrust.state, 'satisfied');
    assert.equal(byId.autoUpdateDelay.state, 'unavailable');
    assert.equal(byId.autoUpdateDelay.valueLabel, 'Not available');
    assert.match(byId.autoUpdateDelay.detail, /1\.125/);
    assert.equal(openCount(rows), 2);
    assert.equal(allSatisfied(rows), false);
});

test('support is probed with defaultValue, not the presence of a global value', () => {
    const rows = readState(inspectOf(safeSettings({
        // A fork that knows the key but publishes no default is still "unsupported".
        'extensions.autoUpdateDelay': { globalValue: 24 }
    })));
    const cooldown = rows.find(r => r.id === 'autoUpdateDelay');
    assert.equal(cooldown.state, 'unavailable');
});

test('workspace-scoped values are never reported as the user state', () => {
    // Global says safe, workspace says on: the row reports the global/user value.
    const withGlobal = readState(inspectOf(safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'off', workspaceValue: 'on' }
    })));
    assert.equal(withGlobal.find(r => r.id === 'automaticTasks').state, 'satisfied');

    // No global value: fall back to the editor default, not the workspace override.
    const withoutGlobal = readState(inspectOf(safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', workspaceValue: 'on' }
    })));
    const row = withoutGlobal.find(r => r.id === 'automaticTasks');
    assert.equal(row.state, 'satisfied');
    assert.equal(row.valueLabel, 'Off');
});

test('inspect errors and a missing inspectFn never throw into the pane', () => {
    const throwing = () => { throw new Error('boom'); };
    assert.equal(readState(throwing).every(r => r.state === 'unavailable'), true);
    assert.equal(readState(undefined).every(r => r.state === 'unavailable'), true);
});

test('all five checks satisfied makes the section one line', () => {
    const rows = readState(inspectOf(safeSettings()));
    assert.equal(openCount(rows), 0);
    assert.equal(allSatisfied(rows), true);
    const html = renderHarden(rows);
    assert.match(html, /data-all-safe="1"/);
    assert.doesNotMatch(html, /data-harden=/);
    assert.match(html, /All 5 checks are in the safe state/);
});

test('renderHarden shows a switch for unsafe rows and none for safe or unavailable', () => {
    const rows = readState(inspectOf(safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.autoUpdateDelay': undefined
    })));
    const html = renderHarden(rows);
    assert.match(html, /data-all-safe="0"/);
    assert.match(html, /data-harden="automaticTasks"/);
    assert.equal((html.match(/data-harden=/g) || []).length, 2); // one switch per unsafe check, never an apply-all
    assert.doesNotMatch(html, /data-harden="autoUpdateDelay"/);
    assert.match(html, /Not available/);
    assert.match(html, /Recommended: Off/);
    assert.match(html, /class="switch is-checked" role="switch" aria-checked="true" data-harden="automaticTasks"/); // tasks on -> switch on
    assert.match(html, /class="switch" role="switch" aria-checked="false" data-harden="trustPrompt"/); // not always -> switch off
    assert.match(html, /class="switch is-safe is-checked" role="switch" aria-checked="true"/); // safe -> green switch
    assert.match(html, /harden__status is-warn/); // unsupported -> !
    assert.doesNotMatch(html, /class="tag/); // no value pill: glyphs only
});

test('renderParts always carries the Harden body and its summary state', () => {
    const parts = renderParts({ status: {}, hardening: readState(inspectOf(safeSettings({ 'security.workspace.trust.enabled': { defaultValue: true, globalValue: false } }))) });
    assert.match(parts.harden, /data-harden="workspaceTrust"/);
    assert.match(parts['harden-state'], /hardenstate__dot--warn/);
    assert.match(parts['harden-state'], />1</); // one check open
    assert.match(parts['harden-state'], /data-url="https:\/\/yeethsecurity\.com\/guides\/vscode-extension-malware\/"/);
    assert.doesNotMatch(parts['harden-state'], /hardenstate__dot--ok/);
});

test('the Harden summary is one word with a circled check when everything is safe', () => {
    const { renderHardenState } = require('../ui/paneSections');
    const safeHtml = renderHardenState(readState(inspectOf(safeSettings())));
    assert.match(safeHtml, /hardenstate__dot--ok/);
    assert.match(safeHtml, /<svg/); // the check glyph
    assert.match(safeHtml, /All checks are in the safe state/);
    assert.match(safeHtml, /Read the article/);

    const openHtml = renderHardenState(readState(inspectOf(safeSettings({ 'extensions.autoUpdateDelay': undefined }))));
    assert.match(openHtml, /hardenstate__dot--warn/);
    assert.match(openHtml, /not available in this editor/);
});

test('applyCheck writes the recommended value only when the check is unsafe', async () => {
    const writes = [];
    const update = async (key, value) => { writes.push([key, value]); };

    const safe = await applyCheck(update, inspectOf(safeSettings()), 'automaticTasks');
    assert.equal(safe.ok, true);
    assert.equal(safe.applied, false);
    assert.equal(safe.noop, true);
    assert.deepEqual(writes, []); // already safe -> no write

    const unsafe = await applyCheck(
        update,
        inspectOf(safeSettings({ 'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' } })),
        'automaticTasks'
    );
    assert.equal(unsafe.ok, true);
    assert.equal(unsafe.applied, true);
    assert.deepEqual(writes, [['task.allowAutomaticTasks', 'off']]);

    const unsupported = await applyCheck(update, inspectOf(safeSettings({ 'extensions.autoUpdateDelay': undefined })), 'autoUpdateDelay');
    assert.equal(unsupported.ok, false);
    assert.equal(unsupported.applied, false);
    assert.match(unsupported.error, /1\.125/);
    assert.equal(writes.length, 1); // still just the one write
});

test('applySetting turns a rejected write into a row message instead of throwing', async () => {
    const result = await applySetting(async () => { throw new Error('Unable to write to policy-managed setting'); }, 'task.allowAutomaticTasks', 'off');
    assert.equal(result.ok, false);
    assert.match(result.error, /policy-managed/);

    const noWriter = await applySetting(undefined, 'task.allowAutomaticTasks', 'off');
    assert.equal(noWriter.ok, false);
});

test('splitSettingKey splits at the last dot and versionBucket is coarse', () => {
    assert.deepEqual(splitSettingKey('task.allowAutomaticTasks'), { section: 'task', name: 'allowAutomaticTasks' });
    assert.deepEqual(splitSettingKey('security.workspace.trust.enabled'), { section: 'security.workspace.trust', name: 'enabled' });
    assert.deepEqual(splitSettingKey('plain'), { section: undefined, name: 'plain' });

    assert.equal(versionBucket('1.108.2'), '<1.109');
    assert.equal(versionBucket('1.109.0'), '1.109-1.124');
    assert.equal(versionBucket('1.124.9'), '1.109-1.124');
    assert.equal(versionBucket('1.125.0'), '1.125+');
    assert.equal(versionBucket('2.0.1'), '1.125+');
    assert.equal(versionBucket(''), 'unknown');
    assert.equal(versionBucket(undefined), 'unknown');
});

// ── Pane wiring: user (Global) scope, one audit entry, one telemetry event ──

function loadPaneWithFakeVscode(options = {}) {
    const calls = { updates: [], audit: [], telemetry: [], statusBar: [] };
    let provider = null;
    let receive = null;
    let view = null;
    const settings = safeSettings();

    const fakeVscode = {
        ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
        version: '1.126.0',
        window: {
            registerWebviewViewProvider: (_id, p) => { provider = p; return { dispose() {} }; },
            setStatusBarMessage: (text) => calls.statusBar.push(text)
        },
        workspace: {
            getConfiguration: (section) => ({
                get: () => undefined,
                inspect: (name) => {
                    const full = section ? `${section}.${name}` : name;
                    return settings[full];
                },
                update: (name, value, target) => {
                    const full = section ? `${section}.${name}` : name;
                    calls.updates.push({ section, name: full, value, target });
                    if (options.reject) return Promise.reject(new Error(options.reject));
                    return Promise.resolve();
                }
            }),
            onDidChangeConfiguration: () => ({ dispose() {} })
        },
        commands: { executeCommand: () => Promise.resolve() },
        env: { openExternal: () => Promise.resolve() },
        Uri: { parse: value => value }
    };

    const originalLoad = Module._load;
    Module._load = function (request, ...rest) {
        if (request === 'vscode') return fakeVscode;
        return originalLoad.call(this, request, ...rest);
    };
    let createPane;
    try {
        // Drop the cached module so each test binds to its own vscode stub.
        delete require.cache[require.resolve('../ui/pane')];
        ({ createPane } = require('../ui/pane'));
    } finally {
        Module._load = originalLoad;
    }

    const pane = createPane({
        history: { listRuns: () => [], listRemoved: () => [], getLastInventory: () => undefined, onChange: () => () => {} },
        audit: { list: () => [], onChange: () => () => {}, record: entry => calls.audit.push(entry) },
        getStatus: () => ({ removalMode: 'auto' }),
        runScan: () => Promise.resolve(),
        telemetry: { record: (name, props) => calls.telemetry.push({ name, props }) }
    });

    view = {
        webview: {
            options: {},
            html: '',
            postMessage: () => Promise.resolve(),
            onDidReceiveMessage: cb => { receive = cb; }
        },
        visible: true,
        onDidChangeVisibility: () => ({ dispose() {} }),
        onDidDispose: () => ({ dispose() {} })
    };
    provider.resolveWebviewView(view);

    return { calls, settings, send: (message) => receive(message), pane, view };
}

const tick = () => new Promise(resolve => setTimeout(resolve, 20));
const applied = calls => calls.telemetry.filter(event => event.name === 'hardening_applied');

test('the harden message writes Global scope, one audit entry, and one telemetry event', async () => {
    const { calls, settings, send } = loadPaneWithFakeVscode();
    settings['task.allowAutomaticTasks'] = { defaultValue: 'off', globalValue: 'on' };

    send({ type: 'harden', check: 'automaticTasks' });
    await tick();

    assert.equal(calls.updates.length, 1);
    assert.deepEqual(calls.updates[0], { section: 'task', name: 'task.allowAutomaticTasks', value: 'off', target: 1 });
    assert.equal(calls.audit.length, 1);
    assert.deepEqual(calls.audit[0], { type: 'hardening', detail: 'task.allowAutomaticTasks' });
    assert.equal(applied(calls).length, 1);
    assert.equal(applied(calls)[0].props.setting, 'task.allowAutomaticTasks');
    assert.equal(applied(calls)[0].props.editor_version, '1.125+');
});

test('clicking Apply on an already-safe row writes nothing and logs nothing', async () => {
    const { calls, send } = loadPaneWithFakeVscode();

    send({ type: 'harden', check: 'automaticTasks' });
    await tick();

    assert.equal(calls.updates.length, 0);
    assert.equal(calls.audit.length, 0);
    assert.equal(applied(calls).length, 0);
});

test('a failed write keeps the reason in the row and records no audit entry', async () => {
    const { calls, settings, send, view } = loadPaneWithFakeVscode({ reject: 'Unable to write to policy-managed setting' });
    settings['security.workspace.trust.enabled'] = { defaultValue: true, globalValue: false };

    send({ type: 'harden', check: 'workspaceTrust' });
    await tick();

    assert.equal(calls.audit.length, 0);
    assert.equal(applied(calls).length, 0);
    assert.match(view.webview.html, /Unable to write to policy-managed setting/);
});
