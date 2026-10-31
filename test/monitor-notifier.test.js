/**
 * Unit tests for `monitor.js` and `notifier.js`.
 *
 * Covers:
 *   - 5-minute poll delay, jitter bounds, server minWaitMs, and exponential backoff
 *   - Notification ledger: no duplicate alerts, batching into one toast per cycle,
 *     re-notify when severity upgrades, and manual command override
 *   - All three `removalMode` branches (`auto`, `prompt`, `warn`), plus fallback
 *     from `auto` to `prompt` when `workbench.extensions.uninstallExtension` fails
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    BASE_POLL_MS,
    POLL_JITTER_MS,
    STARTUP_JITTER_MS,
    MAX_BACKOFF_MS,
    CHANGE_DEBOUNCE_MS,
    computeStartupDelayMs,
    computeNextDelayMs,
    createAdvisoryMonitor
} = require('../monitor');

const {
    handleAuditFindings,
    REMOVAL_GUIDE_URL
} = require('../notifier');

function createFakeContext() {
    const store = new Map();
    return {
        globalState: {
            get: key => store.get(key),
            update: (key, val) => { store.set(key, val); return Promise.resolve(); }
        }
    };
}

function makeFinding(id, version, advisoryId, severity = 'high') {
    return {
        extension: { id, packageJSON: { displayName: id, version } },
        advisory: { id: advisoryId, severity, title: 'Malware', permalink: 'https://www.pkgscan.dev/pkg/test' }
    };
}

test('backoff, startup jitter, and server minWaitMs stay within expected bounds', () => {
    assert.equal(computeStartupDelayMs(() => 0), 0);
    assert.ok(computeStartupDelayMs(() => 0.999) < STARTUP_JITTER_MS);

    // Normal poll: 5 min + jitter.
    const normal = computeNextDelayMs({ failureCount: 0, random: () => 0.5 });
    assert.equal(normal, BASE_POLL_MS + Math.floor(0.5 * POLL_JITTER_MS));

    // Server minWaitMs larger than 5 min is respected.
    const serverHint = computeNextDelayMs({ failureCount: 0, minWaitMs: 10 * 60 * 1000, random: () => 0 });
    assert.equal(serverHint, 10 * 60 * 1000);

    // Exponential backoff caps at 30 minutes + jitter.
    const fail1 = computeNextDelayMs({ failureCount: 1, random: () => 0 });
    const fail2 = computeNextDelayMs({ failureCount: 2, random: () => 0 });
    const fail9 = computeNextDelayMs({ failureCount: 9, random: () => 0 });
    assert.equal(fail1, 2 * 60 * 1000);
    assert.equal(fail2, 4 * 60 * 1000);
    assert.equal(fail9, MAX_BACKOFF_MS);
});

test('executeCycle resolves with the audit result; debounced change cycle is skipped right after an install scan', async t => {
    // Mock setTimeout + fake clock + captured extensions.onDidChange listener, so no real waiting.
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const flush = () => new Promise(r => process.nextTick(r));
    let clock = 1_000_000;
    let fireChange = null;
    const vscodeApi = { extensions: { onDidChange: fn => { fireChange = fn; return { dispose() {} }; } } };
    const triggers = [];
    const monitor = createAdvisoryMonitor({
        vscodeApi,
        now: () => clock,
        startupJitterMs: 60 * 60 * 1000, // keep the startup cycle out of the way
        runAudit: async trigger => { triggers.push(trigger); return { failureCount: 0, flaggedIds: ['a.b'] }; }
    });
    monitor.start();

    // The install path gets the scan outcome back.
    const result = await monitor.executeCycle('install');
    assert.deepEqual(result.flaggedIds, ['a.b']);

    // onDidChange fired by the same install: when the timer fires 5 s later the
    // install scan has just completed, so the duplicate 'change' cycle is dropped.
    fireChange();
    clock += CHANGE_DEBOUNCE_MS - 1;
    t.mock.timers.tick(CHANGE_DEBOUNCE_MS);
    await flush();
    assert.deepEqual(triggers, ['install']);

    // A change with no recent scan still runs the normal 'change' cycle.
    fireChange();
    clock += CHANGE_DEBOUNCE_MS * 3;
    t.mock.timers.tick(CHANGE_DEBOUNCE_MS);
    await flush();
    assert.deepEqual(triggers, ['install', 'change']);
    monitor.dispose();
});

test('ledger prevents duplicate alerts, batches multiple findings, and re-notifies on severity upgrade', async () => {
    const context = createFakeContext();
    const warnings = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        window: {
            showWarningMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return Promise.resolve(undefined);
            },
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };

    const findings = [
        makeFinding('bad.one', '1.0.0', 'adv-1', 'medium'),
        makeFinding('bad.two', '2.0.0', 'adv-2', 'high')
    ];

    // First poll: batches both findings into a single warning notification.
    const first = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'warn' });
    assert.equal(first.notified, 2);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0].msg, /bad\.one.*bad\.two/);

    // Second poll with identical findings: stays completely quiet.
    const second = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'warn' });
    assert.equal(second.notified, 0);
    assert.equal(warnings.length, 1);

    // Third poll where bad.one severity increases from medium -> critical: re-notifies only bad.one.
    const upgraded = [
        makeFinding('bad.one', '1.0.0', 'adv-1', 'critical'),
        makeFinding('bad.two', '2.0.0', 'adv-2', 'high')
    ];
    const third = await handleAuditFindings({ context, vscodeApi, findings: upgraded, trigger: 'poll', removalMode: 'warn' });
    assert.equal(third.notified, 1);
    assert.equal(warnings.length, 2);

    // Manual check always notifies even when already in ledger.
    const manual = await handleAuditFindings({ context, vscodeApi, findings: upgraded, trigger: 'manual', removalMode: 'warn' });
    assert.equal(manual.notified, 2);
});

test('removalMode auto uninstalls silently and falls back to prompt if uninstall throws', async () => {
    const context = createFakeContext();
    const uninstalled = [];
    const warnings = [];

    const vscodeApi = {
        extensions: { all: [] },
        commands: {
            executeCommand: async (cmd, id) => {
                if (cmd === 'workbench.extensions.uninstallExtension') {
                    if (id === 'locked.ext') throw new Error('locked');
                    uninstalled.push(id);
                }
            }
        },
        window: {
            showWarningMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return Promise.resolve(undefined);
            },
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };

    const findings = [
        makeFinding('removed.ext', '1.0.0', 'adv-ok', 'critical'),
        makeFinding('locked.ext', '1.0.0', 'adv-fail', 'critical')
    ];

    const res = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'auto' });
    assert.equal(res.removed, 1);
    assert.deepEqual(uninstalled, ['removed.ext']);
    // One summary notice for removed.ext + one fallback prompt with Uninstall button for locked.ext.
    assert.equal(warnings.length, 2);
    assert.match(warnings[0].msg, /removed malicious extension.*removed\.ext/);
    assert.ok(warnings[0].btns.includes('Reload Window'));
    assert.ok(warnings[0].btns.includes('What to do next'), 'removal toast links to the cleanup guide');
    assert.match(warnings[1].msg, /locked\.ext/);
    assert.ok(warnings[1].btns.includes('Uninstall'));

    // Same findings again (user reinstalled): auto mode removes removed.ext AGAIN
    // (the ledger never blocks removal), but the fallback prompt for locked.ext
    // is ledger-gated so it stays quiet.
    const again = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'auto' });
    assert.equal(again.removed, 1);
    assert.deepEqual(uninstalled, ['removed.ext', 'removed.ext']);
    assert.equal(warnings.length, 3);
    assert.match(warnings[2].msg, /removed malicious extension.*removed\.ext/);
});

test('"What to do next" on the removal toast opens the cleanup guide and records telemetry', async () => {
    const context = createFakeContext();
    const opened = [];
    const events = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        env: { openExternal: uri => { opened.push(uri); } },
        Uri: { parse: s => s },
        window: {
            showWarningMessage: () => Promise.resolve('What to do next'), // user clicks the guide button
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };
    const telemetry = { record: (name, props) => events.push({ name, props }) };
    await handleAuditFindings({ context, vscodeApi, telemetry, findings: [makeFinding('bad.ext', '1', 'adv')], trigger: 'poll', removalMode: 'auto' });
    await new Promise(r => setImmediate(r)); // let the .then() on the toast run
    assert.deepEqual(opened, [REMOVAL_GUIDE_URL]);
    assert.ok(events.some(e => e.name === 'removal_guide_opened' && e.props.from === 'auto_toast'));
});

test('onRemoved callback receives auto removals', async () => {
    const context = createFakeContext();
    const seen = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        window: { showWarningMessage: () => Promise.resolve(undefined), showInformationMessage: () => Promise.resolve(undefined) }
    };
    await handleAuditFindings({
        context, vscodeApi, findings: [makeFinding('gone.ext', '1.0.0', 'adv-1', 'high')],
        trigger: 'poll', removalMode: 'auto', onRemoved: (items, action) => seen.push({ ids: items.map(i => i.extension.id), action })
    });
    assert.deepEqual(seen, [{ ids: ['gone.ext'], action: 'auto' }]);
});
