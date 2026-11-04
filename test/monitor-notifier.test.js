/**
 * Unit tests for `monitor.js` and `notifier.js`.
 *
 * Covers:
 *   - 5-minute poll delay, jitter bounds, server minWaitMs, and exponential backoff
 *   - Notification ledger: no duplicate alerts, batching into one toast per cycle,
 *     re-notify when severity upgrades, and manual command override
 *   - All three `removalMode` branches (`auto`, `manual`, `warn`), plus fallback
 *     from `auto` to `manual` when `workbench.extensions.uninstallExtension` fails
 */

const { test, beforeEach } = require('node:test');
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
    handleFileFindings,
    forgetExtensionsInLedger,
    forgetFileHashesInLedger,
    REMOVAL_GUIDE_URL,
    SEE_MORE_BUTTON,
    dismissActionNotices,
    remindPendingReload,
    resetOpenActionNotices,
    resetShownFileNotices
} = require('../notifier');

// A toast the test does not click. Resolving with no choice would show it again.
function stayOpen() {
    return new Promise(() => {});
}

beforeEach(() => {
    resetOpenActionNotices();
    resetShownFileNotices();
});

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

test('a cycle requested during a running scan runs once more after it finishes', async () => {
    let release = () => {};
    const triggers = [];
    const monitor = createAdvisoryMonitor({
        startupJitterMs: 60 * 60 * 1000,
        runAudit: trigger => {
            triggers.push(trigger);
            if (triggers.length === 1) return new Promise(resolve => { release = () => resolve({ failureCount: 0 }); });
            return Promise.resolve({ failureCount: 0 });
        }
    });
    const first = monitor.executeCycle('poll');
    void monitor.executeCycle('change');
    assert.deepEqual(triggers, ['poll'], 'the running scan is not restarted');
    release();
    await first;
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(triggers, ['poll', 'change']);
    monitor.dispose();
});

test('forgetting an extension in the ledger lets the next poll flag it again', async () => {
    const context = createFakeContext();
    const warnings = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        window: {
            showErrorMessage: msg => { warnings.push(msg); return stayOpen(); },
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };
    const finding = makeFinding('bad.ext', '1.0.0', 'adv-1', 'high');

    await handleAuditFindings({ context, vscodeApi, findings: [finding], trigger: 'poll', removalMode: 'warn' });
    const quiet = await handleAuditFindings({ context, vscodeApi, findings: [finding], trigger: 'poll', removalMode: 'warn' });
    assert.equal(quiet.notified, 0, 'still allowlisted in spirit: the ledger keeps the next poll quiet');

    // This is what a Settings removal does before the follow-up scan.
    assert.equal(forgetExtensionsInLedger(context, ['Bad.Ext']), 1);
    // A file-threat row must survive an extension forget.
    context.globalState.update('devGuard.notificationLedger', {
        ...context.globalState.get('devGuard.notificationLedger'),
        'file::/repo/.git/hooks/pre-push::abc123': { severity: 'high' }
    });
    forgetExtensionsInLedger(context, ['bad.ext']);
    assert.ok(context.globalState.get('devGuard.notificationLedger')['file::/repo/.git/hooks/pre-push::abc123']);

    const again = await handleAuditFindings({ context, vscodeApi, findings: [finding], trigger: 'poll', removalMode: 'warn' });
    assert.equal(again.notified, 1);
    assert.equal(warnings.length, 2);

    // Revoke starts an 'unallow' scan. The old ledger row must not hide it.
    await handleAuditFindings({ context, vscodeApi, findings: [finding], trigger: 'poll', removalMode: 'warn' });
    const revoked = await handleAuditFindings({ context, vscodeApi, findings: [finding], trigger: 'unallow', removalMode: 'warn' });
    assert.equal(revoked.notified, 1, 'a scan after revoke notifies even when the ledger already saw this extension');

    forgetFileHashesInLedger(context, ['ABC123']);
    assert.equal(context.globalState.get('devGuard.notificationLedger')['file::/repo/.git/hooks/pre-push::abc123'], undefined);
});

test('ledger prevents duplicate alerts, batches multiple findings, and re-notifies on severity upgrade', async () => {
    const context = createFakeContext();
    const warnings = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        window: {
            showErrorMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return stayOpen();
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

test('removalMode auto uninstalls silently and falls back to manual if uninstall throws', async () => {
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
            showErrorMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return stayOpen();
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
    assert.ok(warnings[0].btns.every(button => typeof button === 'string'), 'the action notice is a toast, not a dialog');
    assert.ok(warnings[0].btns.includes('What to do next'), 'removal toast links to the cleanup guide');
    assert.match(warnings[1].msg, /locked\.ext/);
    assert.ok(warnings[1].btns.includes('Uninstall'));

    // Same findings again. The toasts are still up, so this scan does not stack
    // copies. It still uninstalls removed.ext again.
    const again = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'auto' });
    assert.equal(again.removed, 1);
    assert.deepEqual(uninstalled, ['removed.ext', 'removed.ext']);
    assert.equal(warnings.length, 2, 'an open toast is not shown a second time');

    // The toasts are gone and the user still has not reloaded or uninstalled.
    // The next scan shows both again.
    resetOpenActionNotices();
    const third = await handleAuditFindings({ context, vscodeApi, findings, trigger: 'poll', removalMode: 'auto' });
    assert.equal(third.removed, 1);
    assert.equal(warnings.length, 4);
    assert.match(warnings[2].msg, /removed malicious extension.*removed\.ext/);
    assert.match(warnings[3].msg, /locked\.ext/);
});

test('"What to do next" on the removal toast opens the cleanup guide and records telemetry', async () => {
    const context = createFakeContext();
    const opened = [];
    const events = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: {
            executeCommand: async (cmd, arg) => {
                if (cmd === 'simpleBrowser.show') opened.push(arg);
            }
        },
        env: { openExternal: uri => { opened.push(`external:${uri}`); } },
        Uri: { parse: s => s },
        window: {
            // The guide is not the decision, so the toast is shown again and stays up.
            showErrorMessage: () => {
                opened.push('toast');
                if (opened.filter(item => item === 'toast').length === 1) return Promise.resolve('What to do next');
                return stayOpen();
            },
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };
    const telemetry = { record: (name, props) => events.push({ name, props }) };
    await handleAuditFindings({ context, vscodeApi, telemetry, findings: [makeFinding('bad.ext', '1', 'adv')], trigger: 'poll', removalMode: 'auto' });
    for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));
    assert.deepEqual(opened.filter(item => item !== 'toast'), [REMOVAL_GUIDE_URL]);
    assert.equal(opened.filter(item => item === 'toast').length, 2, 'What to do next brings the same toast back');
    assert.ok(events.some(e => e.name === 'removal_guide_opened' && e.props.from === 'auto_toast'));
});

function fileFinding() {
    return {
        filePath: '/repo/.vscode/tasks.json',
        displayPath: '.vscode/tasks.json',
        fileName: 'tasks.json',
        sha256: 'abc123',
        severity: 'high',
        scope: 'workspace',
        matches: [{ rule: 'REMOTE_PAYLOAD' }]
    };
}

test('See more opens the pane from the one file-threat notice', async () => {
    resetShownFileNotices();
    const context = createFakeContext();
    let opened = 0;
    let quarantined = 0;
    let progressShown = false;
    const warnings = [];
    const vscodeApi = {
        ProgressLocation: { Notification: 15 },
        window: {
            showErrorMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                // See more is not the decision, so the same toast is shown again.
                if (warnings.length === 1) return Promise.resolve(SEE_MORE_BUTTON);
                return stayOpen();
            },
            withProgress: () => { progressShown = true; }
        }
    };
    const result = await handleFileFindings({
        context,
        vscodeApi,
        findings: [fileFinding()],
        trigger: 'startup',
        onOpenPane: async () => { opened += 1; },
        onQuarantine: async () => { quarantined += 1; }
    });
    for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));
    assert.equal(result.notified, 1);
    assert.equal(progressShown, false, 'there is no second progress notice');
    assert.equal(warnings.length, 2, 'See more brings the same toast back');
    const fileToast = warnings[0];
    assert.ok(fileToast.btns.every(button => typeof button === 'string'), 'the notice is a toast, not a dialog');
    assert.ok(!fileToast.msg.includes('1 minute'));
    assert.ok(fileToast.btns.includes('Quarantine'));
    assert.ok(fileToast.btns.includes('Inspect File'));
    assert.ok(fileToast.btns.includes(SEE_MORE_BUTTON));
    assert.ok(!fileToast.btns.includes('Allow File'), 'the suspicious-file popup has no Allow button');
    assert.ok(!fileToast.btns.includes('Open Dev-Guard'));
    assert.equal(opened, 1);
    assert.equal(quarantined, 0, 'See more is not a quarantine');
});

test('a scan shows a file notice again when that toast is not already up', async () => {
    resetShownFileNotices();
    const context = createFakeContext();
    const warnings = [];
    const vscodeApi = {
        window: {
            showErrorMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return stayOpen();
            }
        }
    };
    const finding = fileFinding();
    // An earlier scan stored the row, and that toast is no longer up.
    context.globalState.update('devGuard.notificationLedger', {
        'file::/repo/.vscode/tasks.json::abc123': { severity: 'high', action: 'file-alerted' }
    });
    const startup = await handleFileFindings({
        context, vscodeApi, findings: [finding], trigger: 'startup'
    });
    assert.equal(startup.notified, 1, 'a scan shows the notice again when it is not already up');
    assert.ok(warnings[0].btns.every(button => typeof button === 'string'), 'the notice is a toast, not a dialog');
    const again = await handleFileFindings({
        context, vscodeApi, findings: [finding], trigger: 'change'
    });
    assert.equal(again.notified, 0, 'another save does not stack a second notice while the first is up');
});

test('a pane action dismisses the file notice and does not quarantine from the toast', async () => {
    resetShownFileNotices();
    const context = createFakeContext();
    let quarantined = 0;
    let shown = 0;
    const commands = [];
    let finish;
    const vscodeApi = {
        commands: {
            executeCommand: async command => { commands.push(command); }
        },
        window: {
            // Stays open until the test closes it, the way a real toast does.
            showErrorMessage: () => {
                shown += 1;
                return new Promise(resolve => { finish = resolve; });
            }
        }
    };
    const result = await handleFileFindings({
        context,
        vscodeApi,
        findings: [fileFinding()],
        trigger: 'change',
        onQuarantine: async () => { quarantined += 1; }
    });
    assert.equal(result.notified, 1);
    await dismissActionNotices(vscodeApi, 'file');
    finish(undefined);
    for (let i = 0; i < 4; i++) await new Promise(r => setImmediate(r));
    assert.equal(quarantined, 0, 'closing the toast from the pane is not a second quarantine');
    assert.equal(shown, 1, 'the pane dismiss does not show the toast again');
    assert.ok(commands.includes('notifications.hideToasts'));
    assert.ok(commands.includes('notification.clear'));
});

test('dismissing the extension notice from the pane is not a refused uninstall', async () => {
    const context = createFakeContext();
    const events = [];
    let finish;
    const vscodeApi = {
        commands: { executeCommand: async () => {} },
        extensions: { all: [] },
        window: {
            showErrorMessage: () => new Promise(resolve => { finish = resolve; }),
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };
    await handleAuditFindings({
        context,
        vscodeApi,
        findings: [makeFinding('stay.ext', '1.0.0', 'adv-stay', 'high')],
        trigger: 'manual',
        removalMode: 'manual',
        telemetry: { record: name => events.push(name) }
    });
    await dismissActionNotices(vscodeApi, 'extension');
    finish(undefined);
    for (let i = 0; i < 4; i++) await new Promise(r => setImmediate(r));
    assert.ok(!events.includes('manual_uninstall_refused'));
});

test('dismissing a file notice leaves an extension notice up', async () => {
    resetShownFileNotices();
    const context = createFakeContext();
    let shown = 0;
    const pending = [];
    const vscodeApi = {
        commands: { executeCommand: async () => {} },
        extensions: { all: [] },
        window: {
            showErrorMessage: () => {
                shown += 1;
                return new Promise(resolve => pending.push(resolve));
            },
            showInformationMessage: () => Promise.resolve(undefined)
        }
    };
    await handleAuditFindings({
        context,
        vscodeApi,
        findings: [makeFinding('stay.ext', '1.0.0', 'adv-stay', 'high')],
        trigger: 'manual',
        removalMode: 'manual'
    });
    await handleFileFindings({
        context,
        vscodeApi,
        findings: [fileFinding()],
        trigger: 'change'
    });
    assert.equal(shown, 2);
    await dismissActionNotices(vscodeApi, 'file');
    // The file toast stays closed. The extension toast is shown again.
    assert.equal(shown, 3);
});

test('closing the file notice with X shows it again and does not quarantine', async () => {
    resetShownFileNotices();
    const context = createFakeContext();
    let quarantined = 0;
    let shown = 0;
    const vscodeApi = {
        window: {
            showErrorMessage: () => {
                shown += 1;
                // The first close is the X. The toast that comes back stays up.
                if (shown === 1) return Promise.resolve(undefined);
                return stayOpen();
            }
        }
    };
    const result = await handleFileFindings({
        context,
        vscodeApi,
        findings: [fileFinding()],
        trigger: 'change',
        onQuarantine: async () => { quarantined += 1; }
    });
    for (let i = 0; i < 4; i++) await new Promise(r => setImmediate(r));
    assert.equal(result.notified, 1);
    assert.equal(shown, 2, 'the X is not an action, so the toast comes back');
    assert.equal(quarantined, 0, 'closing the toast is not a quarantine');
});

test('a later auto scan shows the reload notice when the user has not reloaded', async () => {
    let shown = 0;
    const vscodeApi = {
        commands: { executeCommand: async () => {} },
        window: {
            showErrorMessage: () => {
                shown += 1;
                return stayOpen();
            }
        }
    };
    const notice = {
        names: "'Bad'",
        reportUrl: 'https://www.pkgscan.dev/x',
        extensionId: 'bad.ext',
        severity: 'critical'
    };
    assert.equal(remindPendingReload(vscodeApi, null, notice), true);
    assert.equal(shown, 1);
    assert.equal(remindPendingReload(vscodeApi, null, notice), false, 'an open reload toast is not stacked');
    resetOpenActionNotices();
    assert.equal(remindPendingReload(vscodeApi, null, notice), true);
    assert.equal(shown, 2, 'the next scan shows the reload toast again');
});

test('onRemoved callback receives auto removals', async () => {
    const context = createFakeContext();
    const seen = [];
    const vscodeApi = {
        extensions: { all: [] },
        commands: { executeCommand: async () => {} },
        window: { showErrorMessage: () => stayOpen(), showInformationMessage: () => Promise.resolve(undefined) }
    };
    await handleAuditFindings({
        context, vscodeApi, findings: [makeFinding('gone.ext', '1.0.0', 'adv-1', 'high')],
        trigger: 'poll', removalMode: 'auto', onRemoved: (items, action) => seen.push({ ids: items.map(i => i.extension.id), action })
    });
    assert.deepEqual(seen, [{ ids: ['gone.ext'], action: 'auto' }]);
});
