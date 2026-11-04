// Tests for audit.js: snapshot diffing and the audit log store.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const { snapshotOf, diffSnapshots, revokedExtensionIds, createAuditLog, createSettledInstalledSync, scanAfterInstall, MAX_AUDIT } = require('../audit');

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

test('revokedExtensionIds follows the newest allowlist event, not list order', () => {
    const events = [
        { at: 1000, type: 'allowed', id: 'AckeeBlockchain.tools-for-solidity' },
        { at: 500, type: 'blocked', id: 'AckeeBlockchain.tools-for-solidity', detail: 'high · guarddog' },
        { at: 4000, type: 'installed', id: 'ackeeblockchain.tools-for-solidity' },
        { at: 3000, type: 'unallowed', id: 'ackeeblockchain.tools-for-solidity' },
        { at: 2000, type: 'unallowed', id: 'still.ok' },
        { at: 3500, type: 'allowed', id: 'Still.Ok' }
    ];
    assert.deepEqual(revokedExtensionIds(events, new Set()), ['ackeeblockchain.tools-for-solidity']);
    assert.deepEqual(revokedExtensionIds(events, new Set(['ackeeblockchain.tools-for-solidity'])), []);
});

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

test('a reload that drops and restores extensions is not logged as uninstall plus install', () => {
    const log = createAuditLog(fakeContext());
    log.syncInstalled([ext('golang.go', '0.54.0'), ext('stay.ext', '1')], 1);
    // What the editor reports while enablement is still settling.
    let list = [ext('stay.ext', '1')];
    const scans = [];
    let now = 1000;
    const pending = [];
    const syncer = createSettledInstalledSync({
        settleMs: 1000,
        sync: () => log.syncInstalled(list, now),
        onSettled: events => {
            const added = events.filter(e => e.type === 'installed' || e.type === 'updated');
            if (added.length > 0) scans.push(added.map(e => e.id));
        },
        schedule: (fn) => {
            const handle = { fn };
            pending.push(handle);
            return handle;
        },
        cancel: handle => {
            const index = pending.indexOf(handle);
            if (index >= 0) pending.splice(index, 1);
        }
    });

    const fire = () => {
        const handle = pending[pending.length - 1];
        pending.length = 0;
        handle.fn();
    };

    syncer.scheduleSync();
    assert.equal(log.list().length, 0, 'the partial list is not saved yet');

    // The missing extension comes back before the wait ends.
    list = [ext('stay.ext', '1'), ext('golang.go', '0.54.0')];
    now = 1200;
    syncer.scheduleSync();
    assert.equal(pending.length, 1, 'a new list change replaces the previous wait');
    fire();
    assert.equal(log.list().length, 0, 'a brief disappearance is not an uninstall');
    assert.deepEqual(scans, []);

    // A real install stays in the list, so the settled diff records it once.
    list = [ext('stay.ext', '1'), ext('golang.go', '0.54.0'), ext('new.ext', '1')];
    now = 5000;
    syncer.scheduleSync();
    fire();
    assert.deepEqual(log.list().map(e => [e.type, e.id]), [['installed', 'new.ext']]);
    assert.deepEqual(scans, [['new.ext']]);

    syncer.scheduleSync();
    syncer.dispose();
    assert.equal(pending.length, 0, 'shutdown drops a wait that has not fired');
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

test('audit log syncs blocked marketplace entries across multiple windows via globalStorageUri and deduplicates rapid blocks', () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devguard-audit-'));
    try {
        const ctxWindow1 = { ...fakeContext(), globalStorageUri: { fsPath: tmpDir } };
        const ctxWindow2 = { ...fakeContext(), globalStorageUri: { fsPath: tmpDir } };
        const log1 = createAuditLog(ctxWindow1);
        const log2 = createAuditLog(ctxWindow2);

        // Window 1 (proxy owner) records a blocked download twice within 1 second (manifest + VSIX).
        log1.record({ at: 1000, type: 'blocked', id: 'AckeeBlockchain.tools-for-solidity', version: '1.19.4', detail: 'high · Flagged as malicious by guarddog' });
        log1.record({ at: 1500, type: 'blocked', id: 'AckeeBlockchain.tools-for-solidity', version: '1.19.4', detail: 'high · Flagged as malicious by guarddog' });

        // Rapid duplicate is collapsed to 1 entry, and Window 2 sees it immediately via shared storage.
        assert.equal(log1.list().length, 1);
        assert.equal(log2.list().length, 1);
        assert.equal(log2.list()[0].type, 'blocked');
        assert.equal(log2.list()[0].id, 'ackeeblockchain.tools-for-solidity');
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

