/**
 * ENG-36 / DGV-005: the pane headline must not claim the machine is protected
 * while the Health check below it says an action is still open. On the reported
 * first run the marketplace proxy was configured but needed a restart, three
 * editor checks were unsatisfied, and the hero still read "Protected".
 *
 * These tests pin the single action count (`openActionCount`) and the verdict
 * wording built from it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { readState, openCount, openActionCount } = require('../hardening');
const { computeVerdict } = require('../ui/paneFormat');
const { renderParts } = require('../ui/paneHtml');

function settings(overrides = {}) {
    return {
        'task.allowAutomaticTasks': { defaultValue: 'off', globalValue: 'off' },
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 24 },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'always' },
        'extensions.ignoreRecommendations': { defaultValue: false, globalValue: true },
        'security.workspace.trust.enabled': { defaultValue: true, globalValue: true },
        ...overrides
    };
}

const inspectOf = values => key => values[key];
const rowsOf = values => readState(inspectOf(values));

/** The exact 2026-11-06 first run: 1 extension, clean scan, proxy awaiting restart. */
function reportedFirstRun() {
    const hardening = rowsOf(settings({
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 12 },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.ignoreRecommendations': { defaultValue: false, globalValue: false }
    }));
    return {
        status: { removalMode: 'auto', proxyEnabled: true, proxyNeedsRestart: true },
        runs: [{ at: Date.now(), trigger: 'startup', installed: 1, findings: 0, removed: 0, advisoryCount: 1768 }],
        hardening
    };
}

test('openActionCount adds the marketplace proxy to the unsatisfied checks', () => {
    const safe = rowsOf(settings());
    assert.equal(openCount(safe), 0);
    assert.equal(openActionCount(safe, { proxyEnabled: true }), 0);
    assert.equal(openActionCount(safe, { proxyEnabled: true, proxyNeedsRestart: true }), 1, 'configured but not active until restart');
    assert.equal(openActionCount(safe, { proxyEnabled: false }), 1, 'proxy off is an open action');
    assert.equal(openActionCount([], { proxyEnabled: false }), 1, 'the proxy counts even with no editor rows');

    const reported = rowsOf(settings({
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 12 },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.ignoreRecommendations': { defaultValue: false, globalValue: false }
    }));
    assert.equal(openActionCount(reported, { proxyEnabled: true, proxyNeedsRestart: true }), 4);
});

test('a clean inventory with open health actions is "Partially protected", not "Protected"', () => {
    const hardening = rowsOf(settings({
        'extensions.autoUpdateDelay': { defaultValue: 0, globalValue: 12 },
        'security.workspace.trust.startupPrompt': { defaultValue: 'once', globalValue: 'once' },
        'extensions.ignoreRecommendations': { defaultValue: false, globalValue: false }
    }));
    const verdict = computeVerdict({
        status: { proxyEnabled: true, proxyNeedsRestart: true },
        runs: [{ at: Date.now(), installed: 1, findings: 0, removed: 0 }],
        healthActions: openActionCount(hardening, { proxyEnabled: true, proxyNeedsRestart: true })
    });

    assert.equal(verdict.tone, 'warn');
    assert.equal(verdict.title, 'Partially protected');
    assert.equal(verdict.sub, '4 actions needed · 1 extension clear');
    assert.equal(verdict.flagged, 0, 'the ring still reports the inventory: 0 flagged');
    assert.equal(verdict.checked, 1);
});

test('the all-clear state keeps the Protected headline', () => {
    const verdict = computeVerdict({
        status: { proxyEnabled: true },
        runs: [{ at: Date.now(), installed: 1, findings: 0, removed: 0 }],
        healthActions: 0
    });

    assert.equal(verdict.tone, 'ok');
    assert.equal(verdict.title, 'Protected');
    assert.match(verdict.sub, /^1 extension clear · /);
});

test('live threats and the reload notice outrank the health summary', () => {
    const run = { at: Date.now(), installed: 2, findings: 1, removed: 0 };

    const found = computeVerdict({ status: {}, runs: [run], healthActions: 4 });
    assert.equal(found.tone, 'bad');
    assert.equal(found.title, '1 threat found');

    const removed = computeVerdict({
        status: { pendingReload: 1 },
        runs: [{ at: Date.now(), installed: 2, findings: 1, removed: 1 }],
        healthActions: 4
    });
    assert.equal(removed.tone, 'warn');
    assert.equal(removed.title, '1 threat removed');
    assert.equal(removed.pendingReload, 1);
});

test('a stale feed and open actions are reported together', () => {
    const verdict = computeVerdict({
        status: { failureCount: 2 },
        runs: [{ at: Date.now(), installed: 1, findings: 0, removed: 0, stale: true }],
        healthActions: 4
    });
    assert.equal(verdict.tone, 'warn');
    assert.equal(verdict.title, 'Partially protected');
    assert.equal(verdict.sub, '4 actions needed · feed stale');
});

test('the rendered pane says the same thing as the Health check list below it', () => {
    const data = reportedFirstRun();
    const parts = renderParts(data);

    assert.match(parts.hero, /class="hero hero--warn card"/);
    assert.ok(parts.hero.includes('<div class="banner">Partially protected</div>'));
    assert.ok(parts.hero.includes('4 actions needed · 1 extension clear'));
    assert.ok(!parts.hero.includes('>Protected<'), 'the hero never claims full protection here');

    assert.match(parts.setup, /4 actions needed/, 'the list below reports the same count');
    assert.match(parts.setup, /Action needed · Restart IDE to activate marketplace protection/);
});

test('an all-safe pane still reads Protected and lists no actions', () => {
    const parts = renderParts({
        status: { removalMode: 'auto', proxyEnabled: true },
        runs: [{ at: Date.now(), installed: 1, findings: 0, removed: 0 }],
        hardening: rowsOf(settings())
    });

    assert.match(parts.hero, /class="hero hero--ok card"/);
    assert.ok(parts.hero.includes('<div class="banner">Protected</div>'));
    assert.match(parts.setup, /No recommended actions/);
});

test('the recent-removal guide still appears in the partially protected state', () => {
    const now = Date.now();
    const parts = renderParts({
        ...reportedFirstRun(),
        audit: [{ at: now - 1000, type: 'removed', id: 'bad.ext' }]
    });

    assert.ok(parts.hero.includes('Partially protected'));
    assert.ok(parts.hero.includes('An extension was removed recently.'));
    assert.ok(parts.hero.includes('Security guide'));
});
