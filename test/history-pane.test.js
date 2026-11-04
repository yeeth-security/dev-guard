// Tests for history.js (hashes + store), allowlist.js, and ui/paneHtml.js.
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const {
    sha256, hashExtensions, hashAdvisorySet, hashInventory, createHistoryStore, clampHistoryLimit,
    MAX_RUNS, DEFAULT_HISTORY_LIMIT, MIN_HISTORY_LIMIT, MAX_HISTORY_LIMIT
} = require('../history');
const { normalizeAllowlist, isAllowlisted, isStillOnDisk, filterLiveFindings, diffIdSets } = require('../allowlist');
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

    // What a Settings edit looks like: one id leaves, one id joins.
    const edited = diffIdSets(list, normalizeAllowlist(['other.one', 'new.ext']));
    assert.deepEqual(edited.removed, ['bad.ext']);
    assert.deepEqual(edited.added, ['new.ext']);
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
        status: { registry: 'cursor-marketplace', registryMethod: 'product.json', detectedRegistry: 'cursor-marketplace', marketplaceMode: 'default', marketplaceUrl: '', removalMode: 'manual', lastSyncAt: 1, failureCount: 0, pointer: null },
        runs: [{ at: 1, trigger: 'manual', installed: 3, findings: 1, removed: 1, advisoryCount: 10, advisoryHash: 'a'.repeat(64), inventoryHash: 'b'.repeat(64), source: 'pkgscan.dev', stale: false }],
        extensionThreats: [{ id: '<script>evil</script>', version: '1', severity: 'high', title: 'x', permalink: 'https://pkgscan.dev/x' }],
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
    assert.ok(html.includes('1 threat found'), 'verdict counts the extension that is still installed');
    for (const title of ['Setup', 'Extension threats', 'File threats', 'Scan log', 'Allowed extensions', 'Allowed files', 'Audit log', 'Marketplace', 'Marketplace proxy', 'Mode', 'Feed']) {
        assert.ok(html.includes(title), `missing section ${title}`);
    }
    assert.ok(!html.includes('data-section="inventory"'), 'inventory dropdown is gone');
    assert.ok(!html.includes('data-section="allowlist"'), 'the combined allowlist dropdown is gone');
    const auditAt = html.indexOf('data-section="audit"');
    const setupAt = html.indexOf('data-section="setup"');
    const extThreatAt = html.indexOf('data-section="ext-threats"');
    const fileThreatAt = html.indexOf('data-section="threats"');
    assert.ok(setupAt !== -1 && setupAt < auditAt && auditAt < extThreatAt, 'Audit log sits below Setup');
    assert.ok(extThreatAt < fileThreatAt, 'Extension threats sits above File threats');
    assert.ok(!html.includes('data-section="removed"'), 'the Removed dropdown is now Extension threats');
    const scanAt = html.indexOf('data-section="runs"');
    const extAt = html.indexOf('data-section="allowed-extensions"');
    const fileAt = html.indexOf('data-section="allowed-files"');
    assert.ok(scanAt !== -1 && scanAt < extAt && extAt < fileAt, 'allow dropdowns sit after Scan log');
    assert.match(html, /id="proxy" class="switch__input" type="checkbox" role="switch" aria-checked="true" checked/, 'marketplace proxy renders as a checked switch');
    assert.match(html, /<option value="manual" selected>Manual</, 'mode dropdown selects the active mode');
    assert.ok(!html.includes('<script>evil</script>'), 'extension id must be escaped');
    assert.ok(html.includes(esc('<script>evil</script>')));
    assert.ok(html.includes('data-allow='));
    assert.ok(html.includes('data-remove-extension='), 'Uninstall is available on an extension threat');
    assert.match(html, /id="warn-ext-threats">Action needed</, 'Extension threats header warns while a threat is open');
    assert.equal((html.match(/data-unallow="ok\.ext"/g) || []).length, 2, 'Revoke once in Allowed extensions and once in the audit log');
    assert.ok(html.includes('Installed') && html.includes('new.ext@2.0'));
    // Cleanup guide: once on the extension threat, once on the "removed" audit entry.
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
    const fileHash = 'c'.repeat(64);
    const fileLabel = `.vscode/env-setup.js (${fileHash})`;
    const data = {
        status: { removalMode: 'auto' }, runs: [{ at: 1, trigger: 'poll', installed: 2, findings: 0, removed: 0, advisoryCount: 5 }],
        removed: [],
        audit: [{ at: 2, type: 'file_allowed', id: fileLabel, sha256: fileHash }],
        allowlist: ['ok.ext'],
        allowedFiles: [fileHash],
        allowedFileRecords: [{ name: '.vscode/env-setup.js', hash: fileHash, label: fileLabel }],
        nonce: 'n'
    };
    const parts = renderParts(data);
    const html = renderPane(data);
    for (const [id, fragment] of Object.entries(parts)) {
        assert.ok(html.includes(`id="${id}"`), `page has a container for ${id}`);
        assert.ok(html.includes(fragment), `page embeds the same fragment for ${id}`);
    }
    assert.equal(parts['count-runs'], '1');
    assert.equal(parts['count-allowed-extensions'], '1');
    assert.equal(parts['count-allowed-files'], '1');
    assert.ok(parts['allowed-extensions'].includes('ok.ext'), 'allowlisted extension is listed');
    assert.ok(parts['allowed-files'].includes(fileLabel), 'allowed file is name (hash)');
    assert.ok(!parts['allowed-extensions'].includes(fileHash), 'file hash stays out of the extensions dropdown');
    assert.ok(parts['allowed-extensions'].includes(`data-unallow="ok.ext"`));
    assert.ok(parts['allowed-files'].includes(`data-unallow-file="${fileHash}"`));
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

test('Protected hero warns when an extension or file was removed recently', () => {
    const now = Date.now();
    const guide = 'https://yeethsecurity.com/guides/vscode-extension-malware/#remove';
    const base = {
        status: { pendingReload: 0 },
        runs: [{ at: now, installed: 3, findings: 0, removed: 0 }],
        audit: [],
        allowlist: [],
        nonce: 'n'
    };
    const extension = renderPane({ ...base, audit: [{ at: now - 1000, type: 'removed', id: 'bad.ext' }] });
    assert.ok(extension.includes('Protected'));
    assert.ok(extension.includes('An extension was removed recently.'));
    assert.ok(extension.includes(`data-url="${guide}"`) && extension.includes('Security guide'));
    assert.ok(!extension.includes('id="reload"'), 'the reload button stays on the pending-reload notice');

    const file = renderPane({ ...base, audit: [{ at: now - 1000, type: 'quarantined', id: '.vscode/tasks.json' }] });
    assert.ok(file.includes('A file was quarantined recently.'));
    assert.ok(file.includes('Security guide'));

    const both = renderPane({
        ...base,
        audit: [
            { at: now - 1000, type: 'removed', id: 'bad.ext' },
            { at: now - 2000, type: 'quarantined', id: '.vscode/tasks.json' }
        ]
    });
    assert.ok(both.includes('An extension was removed and a file was quarantined recently.'));

    // Put back, or old enough that it is no longer recent: no warning.
    const restored = renderPane({
        ...base,
        audit: [
            { at: now - 1000, type: 'restored', id: '.vscode/tasks.json' },
            { at: now - 5000, type: 'quarantined', id: '.vscode/tasks.json' }
        ]
    });
    assert.ok(!restored.includes('quarantined recently'));
    const old = renderPane({ ...base, audit: [{ at: now - 48 * 60 * 60 * 1000, type: 'removed', id: 'old.ext' }] });
    assert.ok(!old.includes('removed recently'));
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
    // A file-only run stores findings: 0. The live total still includes the extension.
    const mixed = computeVerdict({
        runs: [run(0, 0)],
        fileThreats: [{}],
        threatCount: 2
    });
    assert.equal(mixed.title, '2 threats found');
    assert.equal(mixed.flagged, 2);
});

// ── Threat names in the hero + Scan log, and "Show more" paging ─────────────

const { describeThreats, activeThreats } = require('../threats');

const flaggedExt = { id: 'bad.ext', packageJSON: { version: '1.2.3' } };
const advisory = { severity: 'critical', title: 'CREDENTIAL_THEFT' };
const hookThreat = {
    displayPath: '.git/hooks/pre-push', severity: 'high',
    matches: [{ rule: 'REMOTE_PAYLOAD', technique: 'T1105' }]
};

test('describeThreats names extensions and files in plain English', () => {
    const list = describeThreats({
        found: [{ extension: flaggedExt, advisory }],
        fileThreats: [hookThreat],
        removedIds: new Set(['bad.ext'])
    });
    assert.deepEqual(list[0], { kind: 'extension', name: 'bad.ext@1.2.3', severity: 'critical', why: 'Credential theft', removed: true });
    assert.deepEqual(list[1], { kind: 'file', name: '.git/hooks/pre-push', severity: 'high', why: 'Remote payload', removed: false });
});

test('hero names the threat under the warning, only when something is found', () => {
    const run = { at: 1, installed: 10, findings: 1, removed: 0, details: describeThreats({ found: [{ extension: flaggedExt, advisory }] }) };
    const base = { status: {}, removed: [], audit: [], allowlist: [], inventory: null, nonce: 'n' };

    const bad = renderParts({ ...base, runs: [run] }).hero;
    assert.ok(bad.includes('bad.ext@1.2.3') && !bad.includes('Credential theft'), 'hero names the extension and not the threat type');
    assert.ok(bad.includes('sev sev--critical'), 'a malicious extension shows its severity in red');

    // A file threat with no scan run yet is also named, without the rule label.
    const fileOnly = renderParts({ ...base, runs: [], fileThreats: [hookThreat] }).hero;
    assert.ok(fileOnly.includes('.git/hooks/pre-push') && !fileOnly.includes('Remote payload'));
    assert.ok(fileOnly.includes('sev sev--high'), 'a file threat shows its severity in red');
    assert.ok(fileOnly.includes('class="eye"') && fileOnly.includes('data-open-section="threats"'), 'the file threat has an eye that opens File threats');
    assert.ok(fileOnly.includes('data-threat-key=".git/hooks/pre-push"'), 'the eye names the file card to flash');
    assert.ok(bad.includes('class="eye"') && bad.includes('data-open-section="ext-threats"'), 'the extension threat has an eye that opens Extension threats');
    assert.ok(bad.includes('data-threat-key="bad.ext@1.2.3"'), 'the eye names the extension card to flash');

    // Clean scan: no threat list.
    const clean = renderParts({ ...base, runs: [{ at: 1, installed: 10, findings: 0, removed: 0 }] }).hero;
    assert.ok(!clean.includes('class="found'));

    // Already-removed extensions are not listed as active threats.
    assert.equal(activeThreats([{ details: [{ kind: 'extension', removed: true }] }], []).length, 0);
});

test('hero says how many more threats there are beyond the first three', () => {
    const fileThreats = Array.from({ length: 5 }, (_, i) => ({ ...hookThreat, displayPath: `hook-${i}` }));
    const hero = renderParts({ status: {}, runs: [], fileThreats, nonce: 'n' }).hero;
    assert.ok(hero.includes('hook-2') && !hero.includes('hook-3'));
    assert.ok(hero.includes('+2 more'));
});

test('hero total includes a live extension and a file threat after a file-only scan', () => {
    const hero = renderParts({
        status: {},
        // A file scan records findings: 0. The extension is still installed.
        runs: [{ at: 1, installed: 14, findings: 0, removed: 0, fileFindings: 1 }],
        extensionThreats: [{ id: 'AckeeBlockchain.tools-for-solidity', version: '1.19.4', severity: 'high', title: 'Flagged as malicious by guarddog' }],
        fileThreats: [hookThreat],
        nonce: 'n'
    }).hero;
    assert.ok(hero.includes('2 threats found'), 'the ring total counts the extension and the file');
    assert.ok(hero.includes('AckeeBlockchain.tools-for-solidity@1.19.4'));
    assert.ok(hero.includes('.git/hooks/pre-push'));
});

test('audit Restore and Revoke sit on the line under the threat type', () => {
    const { audit } = renderParts({
        status: {},
        runs: [],
        audit: [
            { at: 2, type: 'quarantined', id: '.vscode/tasks.json', detail: 'critical · REMOTE_PAYLOAD', filePath: '/repo/.vscode/tasks.json', sha256: 'abc' },
            { at: 1, type: 'file_allowed', id: '.vscode/tasks.json (abc)', sha256: 'abc' }
        ],
        allowedFiles: ['abc'],
        quarantined: [{ filePath: '/repo/.vscode/tasks.json', displayPath: '.vscode/tasks.json', sha256: 'abc', quarantinedPath: '/q/tasks.json' }],
        nonce: 'n'
    });
    assert.match(audit, /evt__line[^>]*>\.vscode\/tasks\.json · critical · REMOTE_PAYLOAD<\/div>\s*<div class="evt__actions">/);
    assert.match(audit, /<div class="evt__actions"><button[^>]*data-restore-file="[^"]*"[^>]*>Restore<\/button>/);
    assert.match(audit, /<div class="evt__actions"><button[^>]*data-unallow-file="abc"[^>]*>Revoke<\/button>/);
    assert.ok(!audit.includes('evt__line mono">.vscode/tasks.json · critical · REMOTE_PAYLOAD<button'), 'the button is not on the threat line');
});

test('Scan log lists what each run found, and rows are marked for paging', () => {
    const details = describeThreats({ found: [{ extension: flaggedExt, advisory }], removedIds: new Set(['bad.ext']) });
    const { runs } = renderParts({ status: {}, runs: [{ at: 1, trigger: 'manual', installed: 5, findings: 1, removed: 1, details }], nonce: 'n' });
    assert.ok(runs.includes('bad.ext@1.2.3') && runs.includes('Credential theft') && runs.includes('removed'));
    assert.ok(!runs.includes('class="eye"'), 'a removed finding has no eye');
    assert.ok(runs.includes('data-row'));
});

test('pane page has a Show more pager for every list section', () => {
    const html = renderPane({ status: {}, runs: [], nonce: 'n' });
    for (const key of ['ext-threats', 'threats', 'runs', 'allowed-extensions', 'allowed-files', 'audit']) {
        assert.ok(html.includes(`id="more-${key}"`), `${key} has a more-button slot`);
    }
    assert.ok(html.includes('const PAGE = 5;'));
    assert.ok(html.includes('delete state.shown[key]'), 'collapsing a dropdown resets Show more');
});
