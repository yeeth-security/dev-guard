// Tests for history.js (hashes + store), allowlist.js, and ui/paneHtml.js.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const {
    sha256, hashExtensions, hashAdvisorySet, hashInventory, createHistoryStore, clampHistoryLimit,
    MAX_RUNS, DEFAULT_HISTORY_LIMIT, MIN_HISTORY_LIMIT, MAX_HISTORY_LIMIT
} = require('../history');
const { normalizeAllowlist, isAllowlisted, isStillOnDisk, filterLiveFindings } = require('../allowlist');
const { esc, renderPane, renderParts } = require('../ui/paneHtml');
const { computeVerdict, humanize } = require('../ui/paneFormat');

// Tiny in-memory stand-in for vscode's globalState Memento.
function fakeContext() {
    const store = new Map();
    return {
        globalState: {
            get: key => store.get(key),
            update: (key, value) => { store.set(key, value); return Promise.resolve(); }
        }
    };
}

const fakeExt = (id, version, pkg = '{}') => ({
    id, extensionPath: `/ext/${id}`, packageJSON: { version }, _pkg: pkg
});

test('hashExtensions skips builtins, sorts by id, and hashes package.json', () => {
    const exts = [
        fakeExt('b.two', '2.0', '{"b":1}'),
        fakeExt('a.one', '1.0', '{"a":1}'),
        { id: 'vscode.git', extensionPath: '/x', packageJSON: { isBuiltin: true } }
    ];
    // path.join uses "\" on Windows, so match on the extension id instead of the prefix.
    const readFileSync = p => exts.find(e => p.includes(e.id))._pkg;
    const rows = hashExtensions(exts, new Map([['a.one', { source: 'gallery' }]]), readFileSync);

    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map(r => r.id), ['a.one', 'b.two']);
    assert.equal(rows[0].hash, sha256('{"a":1}'));
    assert.equal(rows[0].source, 'gallery');
    assert.equal(rows[1].source, 'unknown');
});

test('hashAdvisorySet is order-independent and hashInventory is stable', () => {
    const a = [{ id: 'adv-1' }, { id: 'adv-2' }];
    const b = [{ id: 'adv-2' }, { id: 'adv-1' }];
    assert.equal(hashAdvisorySet(a), hashAdvisorySet(b));
    assert.notEqual(hashAdvisorySet(a), hashAdvisorySet([{ id: 'adv-3' }]));
    const inv = [{ id: 'a', version: '1', hash: 'h' }];
    assert.equal(hashInventory(inv), hashInventory([...inv]));
});

test('devGuard.historyLimit: clamped, read live, and trims the scan log on read and write', () => {
    assert.equal(clampHistoryLimit(undefined), DEFAULT_HISTORY_LIMIT);
    assert.equal(clampHistoryLimit('abc'), DEFAULT_HISTORY_LIMIT);
    assert.equal(clampHistoryLimit(1), MIN_HISTORY_LIMIT);
    assert.equal(clampHistoryLimit(99999), MAX_HISTORY_LIMIT);
    assert.equal(clampHistoryLimit(25.7), 25);

    let limit = 20;
    const store = createHistoryStore(fakeContext(), { getLimit: () => limit });
    for (let i = 0; i < 30; i++) store.recordRun({ at: i, trigger: 'poll' }, null);
    assert.equal(store.listRuns().length, 20);

    // Lowering the setting trims what the pane sees immediately (no new write needed).
    limit = 10;
    assert.equal(store.listRuns().length, 10);
    assert.equal(store.listRuns()[0].at, 29);
});

test('history store records runs newest-first, caps size, and records removals', () => {
    const store = createHistoryStore(fakeContext());
    let changes = 0;
    store.onChange(() => changes++);

    for (let i = 0; i < MAX_RUNS + 5; i++) store.recordRun({ at: i, trigger: 'poll' }, [{ id: 'a' }]);
    assert.equal(store.listRuns().length, MAX_RUNS);
    assert.equal(store.listRuns()[0].at, MAX_RUNS + 4); // newest first
    assert.equal(changes, MAX_RUNS + 5);

    store.recordRemoved([{
        extension: { id: 'bad.ext', packageJSON: { version: '0.1.2' } },
        advisory: { id: 'adv-9', severity: 'critical', title: 'Stealer', permalink: 'https://pkgscan.dev/a/9' }
    }], 'auto', 123);
    assert.deepEqual(store.listRemoved()[0], {
        at: 123, action: 'auto', id: 'bad.ext', version: '0.1.2',
        advisoryId: 'adv-9', severity: 'critical', title: 'Stealer', permalink: 'https://pkgscan.dev/a/9'
    });
});

test('allowlist normalizes ids and filters findings case-insensitively', () => {
    const list = normalizeAllowlist(['  Bad.Ext ', 'other.one', 42, '']);
    assert.ok(isAllowlisted('bad.ext', list));
    assert.ok(isAllowlisted('BAD.EXT', list));
    assert.ok(!isAllowlisted('fine.ext', list));

    const io = { existsSync: () => true, readFileSync: () => { throw new Error('no .obsolete'); } };
    const findings = [{ extension: fakeExt('bad.ext', '1') }, { extension: fakeExt('fine.ext', '1') }];
    assert.deepEqual(filterLiveFindings(findings, list, io).map(f => f.extension.id), ['fine.ext']);
});

test('isStillOnDisk tells a reinstall apart from a pending reload', () => {
    const ext = { extensionPath: path.join('/exts', 'bad.ext-1.0.0') };
    const noObsolete = () => { throw new Error('ENOENT'); };

    // Folder present, no .obsolete → installed (or reinstalled).
    assert.equal(isStillOnDisk(ext, { existsSync: () => true, readFileSync: noObsolete }), true);
    // Folder gone → already uninstalled, waiting for reload.
    assert.equal(isStillOnDisk(ext, { existsSync: () => false, readFileSync: noObsolete }), false);
    // Folder present but marked obsolete (Windows file lock) → treated as uninstalled.
    const obsolete = () => JSON.stringify({ 'bad.ext-1.0.0': true });
    assert.equal(isStillOnDisk(ext, { existsSync: () => true, readFileSync: obsolete }), false);
    // Unknown path → assume installed so we never miss a real threat.
    assert.equal(isStillOnDisk({}, {}), true);
});

test('renderPane escapes untrusted text and shows all sections and controls', () => {
    const html = renderPane({
        status: { registry: 'cursor-marketplace', registryMethod: 'product.json', detectedRegistry: 'cursor-marketplace', marketplaceMode: 'default', marketplaceUrl: '', removalMode: 'prompt', lastSyncAt: 1, failureCount: 0, pointer: null },
        runs: [{ at: 1, trigger: 'manual', installed: 3, findings: 1, removed: 1, advisoryCount: 10, advisoryHash: 'a'.repeat(64), inventoryHash: 'b'.repeat(64), source: 'pkgscan.dev', stale: false }],
        removed: [{ at: 1, id: '<script>evil</script>', version: '1', severity: 'high', action: 'auto', title: 'x', permalink: 'https://pkgscan.dev/x' }],
        audit: [
            { at: 3, type: 'allowed', id: 'ok.ext' },
            { at: 2, type: 'allowed', id: 'ok.ext' },           // older duplicate: no second Revoke button
            { at: 1.5, type: 'removed', id: 'bad.ext', version: '1', detail: 'auto' },
            { at: 1, type: 'installed', id: 'new.ext', version: '2.0' }
        ],
        allowlist: ['ok.ext'],
        inventory: { at: 1, rows: [{ id: 'a.b', version: '1', source: 'gallery', hash: 'c'.repeat(64) }] },
        nonce: 'n0nce'
    });

    assert.ok(html.includes('Secured by <b>pkgscan.dev</b>'));
    assert.ok(html.includes('Default · Cursor<'), 'marketplace dropdown shows the detected registry');
    assert.match(html, /id="marketplaceUrl" class="input is-hidden"/, 'URL box hidden in default mode');
    assert.ok(html.includes('1 threat removed'), 'verdict reflects the latest run');
    for (const title of ['Setup', 'Scan log', 'Removed', 'Audit log', 'Inventory', 'Marketplace', 'Mode', 'Feed']) {
        assert.ok(html.includes(title), `missing section ${title}`);
    }
    assert.match(html, /<option value="prompt" selected>Prompt</, 'mode dropdown selects the active mode');
    assert.ok(!html.includes('<script>evil</script>'), 'extension id must be escaped');
    assert.ok(html.includes(esc('<script>evil</script>')));
    assert.ok(html.includes('data-allow='));
    assert.equal((html.match(/data-unallow="ok\.ext"/g) || []).length, 1, 'exactly one Revoke per allowlisted id');
    assert.ok(html.includes('Installed') && html.includes('new.ext@2.0'));
    // Cleanup guide: once on the Removed card, once on the "removed" audit entry.
    const guide = 'https://yeethsecurity.com/guides/vscode-extension-malware/#remove';
    assert.equal((html.match(new RegExp(`data-url="${guide}"`, 'g')) || []).length, 2, 'What to do next link on removal entries');
    assert.ok(html.includes('What to do next ↗'));
    assert.ok(html.includes(`nonce="n0nce"`));
    assert.ok(html.includes(`data-copy="${'a'.repeat(64)}"`), 'full hash available for copy');
    assert.ok(html.includes('⌗aaaaaaaa'), 'hash is shortened for display');
});

test('renderPane custom marketplace shows the URL box and a host-mapping hint', () => {
    const base = { runs: [], removed: [], audit: [], allowlist: [], inventory: null, nonce: 'n' };
    const known = renderPane({ ...base, status: { marketplaceMode: 'custom', marketplaceUrl: 'https://open-vsx.org/vscode/gallery', registry: 'openvsx', detectedRegistry: 'cursor-marketplace' } });
    assert.match(known, /id="marketplaceUrl" class="input " type="url" value="https:\/\/open-vsx\.org\/vscode\/gallery"/);
    assert.ok(known.includes('Matches Open VSX'));
    assert.match(known, /<option value="custom" selected>/);

    const unknown = renderPane({ ...base, status: { marketplaceMode: 'custom', marketplaceUrl: 'https://gallery.example.com', registry: null } });
    assert.ok(unknown.includes('Unknown host · checking all marketplaces'));

    const pending = renderPane({ ...base, status: { marketplaceMode: 'custom', marketplaceUrl: '', registry: 'cursor-marketplace' } });
    assert.ok(pending.includes('Enter your gallery URL to apply'));
});

test('renderParts keys every fragment by a DOM id present in the full page', () => {
    const data = {
        status: { removalMode: 'auto' }, runs: [{ at: 1, trigger: 'poll', installed: 2, findings: 0, removed: 0, advisoryCount: 5 }],
        removed: [], audit: [], allowlist: [], inventory: { at: 1, rows: [{ id: 'a.b', version: '1', source: 'gallery', hash: 'c'.repeat(64) }] }, nonce: 'n'
    };
    const parts = renderParts(data);
    const html = renderPane(data);
    for (const [id, fragment] of Object.entries(parts)) {
        assert.ok(html.includes(`id="${id}"`), `page has a container for ${id}`);
        assert.ok(html.includes(fragment), `page embeds the same fragment for ${id}`);
    }
    assert.equal(parts['count-runs'], '1');
    assert.equal(parts['count-inventory'], '1');
    assert.ok(parts.inventory.includes('class="inv__id">a.b'), 'inventory rows are stacked');
    // Install source (plain English, not "gallery") comes first, SHA chip below it.
    assert.match(parts.inventory, /inv__src">From the marketplace<[^]*?inv__meta">.*data-copy=/);
    assert.ok(!/>gallery</.test(parts.inventory));
    assert.ok(html.includes('data-section="runs"') && html.includes("post('ready')"));
});

test('renderPane shows the reload notice only while a removed extension is still loaded', () => {
    const base = { runs: [{ at: 1, installed: 3, findings: 1, removed: 1 }], removed: [], audit: [], allowlist: [], inventory: null, nonce: 'n' };
    const pending = renderPane({ ...base, status: { pendingReload: 1 } });
    assert.ok(pending.includes('class="hero hero--warn card"'), 'verdict is amber while reload is pending');
    assert.ok(pending.includes('id="reload"') && pending.includes('Reload window'));
    assert.ok(pending.includes('Removed extensions stay loaded until you reload.'));
    assert.ok(/class="notice">[^]*?data-url="https:\/\/yeethsecurity\.com\/guides\/vscode-extension-malware\/#remove"/.test(pending), 'guide link inside the notice');

    const done = renderPane({ ...base, status: { pendingReload: 0 } });
    assert.ok(done.includes('class="hero hero--ok card"'));
    assert.ok(!done.includes('id="reload"'));
});

test('renderPane disables the scan button while scanning', () => {
    const base = { status: {}, runs: [], removed: [], audit: [], allowlist: [], inventory: null, nonce: 'n' };
    assert.match(renderPane({ ...base, scanning: true }), /id="scan" class="btn" disabled>.*Scanning…/);
    assert.match(renderPane({ ...base }), /id="scan" class="btn" ><svg[^]*?<\/svg>Run scan</);
    assert.ok(renderPane({ ...base }).includes('Not scanned yet'));
});

test('computeVerdict picks the right tone and humanize cleans advisory labels', () => {
    const run = (findings, removed, stale = false) => ({ at: 1, installed: 10, findings, removed, stale });
    assert.equal(computeVerdict({ runs: [run(0, 0)] }).tone, 'ok');
    assert.equal(computeVerdict({ runs: [run(1, 1)] }).title, '1 threat removed');
    assert.equal(computeVerdict({ runs: [run(2, 0)] }).title, '2 threats found');
    // Removed but still loaded: amber until the window reloads, even if a later
    // poll reported nothing removed.
    const pending = computeVerdict({ status: { pendingReload: 1 }, runs: [run(0, 0)] });
    assert.equal(pending.tone, 'warn');
    assert.equal(pending.title, '1 threat removed');
    assert.match(pending.sub, /^reload to finish/);
    assert.equal(computeVerdict({ status: { pendingReload: 0 }, runs: [run(1, 1)] }).tone, 'ok', 'green once reloaded');
    assert.equal(computeVerdict({ runs: [run(0, 0, true)] }).tone, 'warn');
    assert.equal(computeVerdict({ runs: [], scanning: true }).tone, 'busy');
    assert.equal(humanize('CREDENTIAL_THEFT'), 'Credential theft');
});
