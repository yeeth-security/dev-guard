/**
 * Unit tests for `hardening.js` (the five editor health checks) and the
 * Setup health check UI inside the Dev-Guard side pane.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');

const {
    CHECKS, readState, openCount, allSatisfied, applySetting, applyCheck,
    summarizeHealthPosture, notifyUnmetHealthChecks, splitSettingKey, versionBucket
} = require('../hardening');
const { renderHealthCheck, HARDEN_GUIDE_URL } = require('../ui/paneSections');
const { renderParts, renderPane } = require('../ui/paneHtml');

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

const inspectOf = settings => key => settings[key];

test('readState resolves satisfied, unsatisfied, and unavailable checks from inspect()', () => {
    const settings = safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.autoUpdateDelay': undefined
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
    assert.equal(openCount(rows), 2);
    assert.equal(allSatisfied(rows), false);
});

test('support is probed via defaultValue and workspace values are ignored', () => {
    const rows = readState(inspectOf(safeSettings({
        'extensions.autoUpdateDelay': { globalValue: 24 },
        'task.allowAutomaticTasks': { defaultValue: 'off', workspaceValue: 'on' }
    })));
    const byId = Object.fromEntries(rows.map(r => [r.id, r]));
    assert.equal(byId.autoUpdateDelay.state, 'unavailable');
    assert.equal(byId.automaticTasks.state, 'satisfied');
    assert.equal(byId.automaticTasks.valueLabel, 'Off');
});

test('Cursor IDE uses extensions.installCooldownHours for Auto-update delay check and applyCheck', async () => {
    const cursorSettings = safeSettings({
        'extensions.autoUpdateDelay': undefined,
        'extensions.installCooldownHours': { defaultValue: 0, globalValue: 0 }
    });
    const rowsUnsatisfied = readState(inspectOf(cursorSettings), { appName: 'Cursor' });
    const delayRow = rowsUnsatisfied.find(r => r.id === 'autoUpdateDelay');
    assert.equal(delayRow.key, 'extensions.installCooldownHours');
    assert.equal(delayRow.state, 'unsatisfied');
    assert.equal(delayRow.valueLabel, 'Off');
    assert.equal(delayRow.sub, 'Action needed · Extension updates install with no delay');
    assert.equal(delayRow.recommendedLabel, '24 h');

    // When delay is positive but below 24h (e.g. 12h), it shows a warning with the 12h value instead of "no delay".
    cursorSettings['extensions.installCooldownHours'] = { defaultValue: 0, globalValue: 12 };
    const delay12 = readState(inspectOf(cursorSettings), { appName: 'Cursor' }).find(r => r.id === 'autoUpdateDelay');
    assert.equal(delay12.state, 'unsatisfied');
    assert.equal(delay12.valueLabel, '12 h');
    assert.equal(delay12.sub, 'Action needed · Delay is 12 h (below 24 h)');
    assert.match(delay12.detail, /only wait 12 h/);

    const writes = [];
    const res = await applyCheck(
        async (k, v) => { writes.push([k, v]); cursorSettings[k] = { defaultValue: 0, globalValue: v }; },
        inspectOf(cursorSettings),
        'autoUpdateDelay',
        { appName: 'Cursor' }
    );
    assert.equal(res.ok, true);
    assert.equal(res.applied, true);
    assert.deepEqual(writes, [['extensions.installCooldownHours', 24]]);

    const rowsSatisfied = readState(inspectOf(cursorSettings), { appName: 'Cursor' });
    const delay24 = rowsSatisfied.find(r => r.id === 'autoUpdateDelay');
    assert.equal(delay24.state, 'satisfied');
    assert.equal(delay24.valueLabel, '24 h');
    assert.equal(delay24.sub, 'No recommended actions · Updates wait 24 h before installing');

    // Values above 24h (e.g. 168h) are also satisfied (green).
    cursorSettings['extensions.installCooldownHours'] = { defaultValue: 0, globalValue: 168 };
    const delay168 = readState(inspectOf(cursorSettings), { appName: 'Cursor' }).find(r => r.id === 'autoUpdateDelay');
    assert.equal(delay168.state, 'satisfied');
    assert.equal(delay168.valueLabel, '168 h');
    assert.equal(delay168.sub, 'No recommended actions · Updates wait 168 h before installing');
});

test('Setup renders Mode above Health check and includes Marketplace proxy inside Health check', async () => {
    const hardening = readState(inspectOf(safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' }
    })));
    const parts = renderParts({ status: { removalMode: 'auto', proxyEnabled: true }, hardening });
    const modeIdx = parts.setup.indexOf('for="mode"');
    const hcIdx = parts.setup.indexOf('Health check');
    const proxyIdx = parts.setup.indexOf('for="proxy"');

    assert.ok(modeIdx > -1 && hcIdx > -1 && proxyIdx > -1, 'Mode, Health check, and Marketplace proxy are in Setup');
    assert.ok(modeIdx < hcIdx, 'Mode is placed above Health check');
    assert.ok(hcIdx < proxyIdx, 'Marketplace proxy row is inside the Health check list');
    assert.match(parts.setup, /1 action needed/);
    assert.match(parts.setup, /data-harden-arm="automaticTasks"/, 'first click arms the unsatisfied check row');
    assert.match(parts.setup, /data-harden="automaticTasks"/, 'second click on the morphed icon applies the setting');
    assert.match(parts.setup, /class="hc__glyph hc__glyph--warn"/, 'unarmed badge glyph is rendered');
    assert.match(parts.setup, /class="hc__glyph hc__glyph--apply"/, 'armed apply glyph is rendered for morph animation');
    assert.match(parts.setup, /class="hc__info"/, 'hoverable info button is rendered');
    assert.match(parts.setup, /role="tooltip"/, 'hover tooltip explains the check');
    assert.equal((parts.setup.match(new RegExp(`data-url="${HARDEN_GUIDE_URL}"`, 'g')) || []).length, 1, 'guide link is in the Health check section footer, not repeated inside popups');
    assert.match(parts.setup, /Read the editor security guide ↗/);
    assert.match(parts.setup, /hc__badge--warn/);
    assert.match(parts.setup, /hc__badge--ok/);

    const allSafeHtml = renderHealthCheck(readState(inspectOf(safeSettings())), { proxyEnabled: true });
    assert.match(allSafeHtml, /No recommended actions/);
    assert.doesNotMatch(allSafeHtml, /data-harden=/);
    assert.doesNotMatch(allSafeHtml, /data-harden-arm=/);

    const proxyOffHtml = renderHealthCheck(readState(inspectOf(safeSettings())), { proxyEnabled: false });
    assert.match(proxyOffHtml, /1 action needed/);

    // When the proxy was just configured on first install (`proxyNeedsRestart: true`), Health check warns and shows "Restart now".
    const proxyRestartHtml = renderHealthCheck(readState(inspectOf(safeSettings())), { proxyEnabled: true, proxyNeedsRestart: true });
    assert.match(proxyRestartHtml, /1 action needed/);
    assert.match(proxyRestartHtml, /Action needed · Restart IDE to activate marketplace protection/);
    assert.match(proxyRestartHtml, /data-reload="proxy">Restart now<\/button>/);

    // Startup health check warning notifies when any items are unmet and stays silent when all are met.
    const warnings = [];
    let opened = false;
    const unmetCount = notifyUnmetHealthChecks({
        inspectFn: inspectOf(safeSettings({ 'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' } })),
        proxyEnabled: false,
        showWarning: (msg, btn) => { warnings.push({ msg, btn }); return Promise.resolve('Review Health Check'); },
        onOpenPane: () => { opened = true; }
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(unmetCount, 2);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0].msg, /2 health check items are not met \(Auto-run tasks, Marketplace proxy\)/);
    assert.equal(opened, true);
    assert.equal(notifyUnmetHealthChecks({ inspectFn: inspectOf(safeSettings()), proxyEnabled: true, showWarning: () => { throw new Error('should not warn'); } }), 0);
});

test('applyCheck writes recommended value only when unsatisfied', async () => {
    const writes = [];
    const update = async (key, value) => { writes.push([key, value]); };

    const safe = await applyCheck(update, inspectOf(safeSettings()), 'automaticTasks');
    assert.equal(safe.ok, true);
    assert.equal(safe.applied, false);
    assert.deepEqual(writes, []);

    const unsafe = await applyCheck(
        update,
        inspectOf(safeSettings({ 'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' } })),
        'automaticTasks'
    );
    assert.equal(unsafe.ok, true);
    assert.equal(unsafe.applied, true);
    assert.deepEqual(writes, [['task.allowAutomaticTasks', 'off']]);

    const rejected = await applySetting(async () => { throw new Error('Policy-managed'); }, 'task.allowAutomaticTasks', 'off');
    assert.equal(rejected.ok, false);
    assert.match(rejected.error, /Policy-managed/);
    assert.deepEqual(splitSettingKey('security.workspace.trust.enabled'), { section: 'security.workspace.trust', name: 'enabled' });
    assert.equal(versionBucket('1.125.0'), '1.125+');
});

test('pane harden message updates Global setting, records audit, and emits telemetry', async () => {
    const calls = { updates: [], audit: [], telemetry: [] };
    let provider = null;
    let receive = null;
    const settings = safeSettings({ 'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' } });

    const fakeVscode = {
        ConfigurationTarget: { Global: 1 },
        version: '1.126.0',
        window: {
            registerWebviewViewProvider: (_id, p) => { provider = p; return { dispose() {} }; },
            setStatusBarMessage: () => {}
        },
        workspace: {
            getConfiguration: section => ({
                get: () => undefined,
                inspect: name => settings[section ? `${section}.${name}` : name],
                update: (name, value, target) => {
                    calls.updates.push({ name: `${section}.${name}`, value, target });
                    return Promise.resolve();
                }
            }),
            onDidChangeConfiguration: () => ({ dispose() {} })
        },
        commands: { executeCommand: () => Promise.resolve() },
        env: { openExternal: () => Promise.resolve() },
        Uri: { parse: v => v }
    };

    const originalLoad = Module._load;
    Module._load = function (request, ...rest) {
        if (request === 'vscode') return fakeVscode;
        return originalLoad.call(this, request, ...rest);
    };
    let createPane;
    try {
        delete require.cache[require.resolve('../ui/pane')];
        ({ createPane } = require('../ui/pane'));
    } finally {
        Module._load = originalLoad;
    }

    createPane({
        history: { listRuns: () => [], listRemoved: () => [], getLastInventory: () => undefined, onChange: () => () => {} },
        audit: { list: () => [], onChange: () => () => {}, record: e => calls.audit.push(e) },
        getStatus: () => ({ removalMode: 'auto' }),
        runScan: () => Promise.resolve(),
        telemetry: { record: (name, props) => calls.telemetry.push({ name, props }) }
    });

    provider.resolveWebviewView({
        webview: { options: {}, html: '', postMessage: () => Promise.resolve(), onDidReceiveMessage: cb => { receive = cb; } },
        visible: true,
        onDidChangeVisibility: () => ({ dispose() {} }),
        onDidDispose: () => ({ dispose() {} })
    });

    receive({ type: 'harden', check: 'automaticTasks' });
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(calls.updates, [{ name: 'task.allowAutomaticTasks', value: 'off', target: 1 }]);
    assert.deepEqual(calls.audit, [{ type: 'hardening', detail: 'task.allowAutomaticTasks' }]);
    const appliedEvent = calls.telemetry.find(e => e.name === 'hardening_applied');
    assert.equal(appliedEvent.props.setting, 'task.allowAutomaticTasks');
    assert.equal(appliedEvent.props.check_id, 'automaticTasks');

    // Clicking "Secured by pkgscan.dev" header badge, "Read the editor security guide", and a pkgscan report link emit distinct telemetry.
    receive({ type: 'pkgscan' });
    receive({ type: 'openUrl', url: HARDEN_GUIDE_URL });
    receive({ type: 'openUrl', url: 'https://www.pkgscan.dev/pkg/vscode-extension/evil/bad-ext@1.0.0' });
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.ok(calls.telemetry.some(e => e.name === 'pkgscan_opened' && e.props.source === 'pane_header'));
    assert.ok(calls.telemetry.some(e => e.name === 'security_guide_opened' && e.props.from === 'pane_health_check'));
    assert.ok(calls.telemetry.some(e => e.name === 'pkgscan_opened' && e.props.source === 'pane_extension_report'));
});

test('telemetry recordState and recordOnce deduplicate health posture and repeated events per user', async () => {
    const store = new Map([['devGuard.telemetryNoticeVersion', 1]]);
    const context = {
        extension: { packageJSON: { version: '0.1.3' } },
        globalState: {
            get: k => store.get(k),
            update: async (k, v) => { store.set(k, v); }
        }
    };
    const batches = [];
    let clock = 1_000_000;
    const fakeVscode = {
        version: '1.144.1',
        env: { isTelemetryEnabled: true, appName: 'Visual Studio Code', appHost: 'desktop' },
        workspace: { getConfiguration: () => ({ get: (_k, d) => d }) }
    };

    const originalLoad = Module._load;
    Module._load = function (request, ...rest) {
        if (request === 'vscode') return fakeVscode;
        return originalLoad.call(this, request, ...rest);
    };
    let createTelemetry;
    try {
        delete require.cache[require.resolve('../telemetry')];
        ({ createTelemetry } = require('../telemetry'));
    } finally {
        Module._load = originalLoad;
    }

    const telemetry = createTelemetry(context, {
        vscodeApi: fakeVscode,
        now: () => clock,
        autoFlushMs: 0,
        fetchImpl: async (_url, opts) => {
            batches.push(JSON.parse(opts.body));
            return { ok: true, status: 200 };
        }
    });

    const settings = safeSettings({
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'on' },
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 12 }
    });

    // 1. First startup check records `health_check_posture`, `health_check_warning_shown`, and `health_check_warning_action`.
    notifyUnmetHealthChecks({
        inspectFn: inspectOf(settings),
        editorVersion: '1.144.1',
        proxyEnabled: true,
        showWarning: () => Promise.resolve('Review Health Check'),
        telemetry
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    await telemetry.flush();
    assert.equal(batches.length, 1);
    const firstEvents = batches[0].events;
    const postureEvt = firstEvents.find(e => e.name === 'health_check_posture');
    assert.equal(postureEvt.props.unmet_count, 2);
    assert.equal(postureEvt.props.automatic_tasks, 'unsatisfied');
    assert.equal(postureEvt.props.auto_update_delay, 'unsatisfied');
    assert.equal(postureEvt.props.auto_update_delay_hours, 12);
    assert.ok(firstEvents.some(e => e.name === 'health_check_warning_shown' && e.props.unmet_count === 2));
    assert.ok(firstEvents.some(e => e.name === 'health_check_warning_action' && e.props.action === 'review'));

    // 2. Second startup with the exact same settings does NOT re-send `health_check_posture` or `health_check_warning_shown`.
    notifyUnmetHealthChecks({
        inspectFn: inspectOf(settings),
        editorVersion: '1.144.1',
        proxyEnabled: true,
        showWarning: () => Promise.resolve(undefined), // user dismissed
        telemetry
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    await telemetry.flush();
    // Only the `dismiss` action is sent; posture and warning_shown were deduplicated!
    assert.equal(batches.length, 2);
    assert.deepEqual(batches[1].events.map(e => e.name), ['health_check_warning_action']);
    assert.equal(batches[1].events[0].props.action, 'dismiss');

    // 3. Dismissing again within 24h is suppressed by `recordOnce`.
    notifyUnmetHealthChecks({
        inspectFn: inspectOf(settings),
        editorVersion: '1.144.1',
        proxyEnabled: true,
        showWarning: () => Promise.resolve(undefined),
        telemetry
    });
    await new Promise(resolve => setTimeout(resolve, 10));
    await telemetry.flush();
    assert.equal(batches.length, 2, 'no telemetry batch sent when posture and dismissal are unchanged');

    // 4. When the user fixes their settings (`unmet_count` drops from 2 -> 0), `health_check_posture` IS sent with the new state.
    settings['task.allowAutomaticTasks'] = { defaultValue: 'off', globalValue: 'off' };
    settings['extensions.autoUpdateDelay'] = { defaultValue: 0, globalValue: 24 };
    notifyUnmetHealthChecks({
        inspectFn: inspectOf(settings),
        editorVersion: '1.144.1',
        proxyEnabled: true,
        telemetry
    });
    await telemetry.flush();
    assert.equal(batches.length, 3);
    assert.equal(batches[2].events.length, 1);
    assert.equal(batches[2].events[0].name, 'health_check_posture');
    assert.equal(batches[2].events[0].props.unmet_count, 0);
    assert.equal(batches[2].events[0].props.all_safe, true);
    assert.equal(batches[2].events[0].props.auto_update_delay_hours, 24);
});

