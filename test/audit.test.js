// Tests for audit.js: snapshot diffing and the audit log store.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const { snapshotOf, diffSnapshots, createAuditLog, scanAfterInstall, MAX_AUDIT } = require('../audit');

function fakeContext() {
    const store = new Map();
    return {
        globalState: {
            get: key => store.get(key),
            update: (key, value) => { store.set(key, value); return Promise.resolve(); }
        }
    };
}

const ext = (id, version, isBuiltin = false) => ({ id, packageJSON: { version, isBuiltin } });

test('snapshotOf skips builtins and lower-cases ids', () => {
    const snap = snapshotOf([ext('Pub.One', '1.0.0'), ext('vscode.git', '1.0.0', true), null]);
    assert.deepEqual(snap, { 'pub.one': '1.0.0' });
});

test('diffSnapshots reports installs, updates, uninstalls, and skips DevGuard removals', () => {
    const previous = { 'a.keep': '1', 'b.gone': '1', 'c.removed': '1', 'd.bump': '1' };
    const current = { 'a.keep': '1', 'd.bump': '2', 'e.new': '1' };
    const lastEventFor = id => (id === 'c.removed' ? { type: 'removed' } : null);

    const events = diffSnapshots(previous, current, 123, lastEventFor);
    assert.deepEqual(events.map(e => [e.type, e.id]), [
        ['updated', 'd.bump'],
        ['installed', 'e.new'],
        ['uninstalled', 'b.gone']
        // c.removed is NOT listed: DevGuard already logged it as "removed".
    ]);
    assert.equal(events[0].detail, 'from 1');
    assert.ok(events.every(e => e.at === 123));
});

test('audit log: first sync is baseline only, later syncs record changes newest-first', () => {
    const log = createAuditLog(fakeContext());
    let changes = 0;
    log.onChange(() => changes++);

    assert.deepEqual(log.syncInstalled([ext('a.one', '1')], 1), []);
    assert.equal(log.list().length, 0, 'fresh install must not log every existing extension');

    log.syncInstalled([ext('a.one', '1'), ext('b.two', '1')], 2);
    log.record({ type: 'allowed', id: 'B.Two', at: 3 });

    const list = log.list();
    assert.deepEqual(list.map(e => [e.type, e.id]), [['allowed', 'b.two'], ['installed', 'b.two']]);
    assert.equal(log.lastEventFor('b.two').type, 'allowed');
    assert.equal(changes, 2);
});

test('scanAfterInstall runs an install-triggered scan and logs clear/flagged per extension', async () => {
    const log = createAuditLog(fakeContext());
    const triggers = [];
    const monitor = { executeCycle: async t => { triggers.push(t); return { flaggedIds: ['evil.ext'] }; } };

    await scanAfterInstall(monitor, log, [{ id: 'Good.Ext', version: '1' }, { id: 'Evil.Ext', version: '2' }]);

    assert.deepEqual(triggers, ['install']);
    const scanned = log.list().filter(e => e.type === 'scanned');
    assert.deepEqual(scanned.map(e => [e.id, e.flagged, e.detail]), [
        ['evil.ext', true, 'after install · flagged'],
        ['good.ext', false, 'after install · clear']
    ]);

    // A scan that returns nothing useful (error path) still records a "clear" entry rather than crashing.
    await scanAfterInstall({ executeCycle: async () => undefined }, log, [{ id: 'x.y' }]);
    assert.equal(log.lastEventFor('x.y').flagged, false);
});

test('install → scan → auto-remove reads in order and logs the removal once', async () => {
    const log = createAuditLog(fakeContext());
    const id = 'evil.ext';
    // t=100 installed (snapshot diff). Scan starts at t=200 and, inside the
    // cycle, uninstalls the extension: onDidChange fires first (t=300, logged as
    // "uninstalled" by syncInstalled), then onRemoved logs "removed" (t=400).
    log.syncInstalled([], 50);
    log.syncInstalled([ext(id, '1')], 100);
    const monitor = {
        executeCycle: async () => {
            log.syncInstalled([], 300); // the race: uninstall seen before "removed" is written
            log.record({ at: 400, type: 'removed', id, version: '1', detail: 'auto' });
            return { startedAt: 200, flaggedIds: [id] };
        }
    };
    await scanAfterInstall(monitor, log, [{ id, version: '1' }]);

    assert.deepEqual(log.list().map(e => [e.type, e.at]), [
        ['removed', 400],
        ['scanned', 200],   // stamped with scan start, so it sorts before the removal
        ['installed', 100]  // no duplicate "uninstalled"
    ]);
});

test('audit log caps at MAX_AUDIT entries by default and honours devGuard.historyLimit', () => {
    const log = createAuditLog(fakeContext());
    for (let i = 0; i < MAX_AUDIT + 10; i++) log.record({ type: 'mode', detail: String(i), at: i });
    assert.equal(log.list().length, MAX_AUDIT);
    assert.equal(log.list()[0].detail, String(MAX_AUDIT + 9)); // newest first

    const small = createAuditLog(fakeContext(), { getLimit: () => 10 });
    for (let i = 0; i < 15; i++) small.record({ type: 'mode', detail: String(i), at: i });
    assert.equal(small.list().length, 10);
});
