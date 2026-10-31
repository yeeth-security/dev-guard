/**
 * Unit tests for `advisories/state.js`, `advisories/registry.js`, and `advisories/sync.js`.
 *
 * Covers:
 *   - Pointer advances only on success, never on failure
 *   - 10-minute overlap window and de-duplication by advisory ID
 *   - Long-gap (>14d), daily (>24h), and corrupt-state full resync triggers
 *   - Marketplace registry detection from product.json and appName fallback
 *   - Per-extension provenance matching (gallery vs sideloaded VSIX, platform, REMOVED state)
 *   - ETag 304 Not Modified and withdrawn advisory removal
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    OVERLAP_MS,
    MAX_GAP_MS,
    FULL_SYNC_INTERVAL_MS,
    defaultSyncState,
    loadSyncState,
    shouldForceFullSync,
    hasReachedPointer,
    recordSyncSuccess,
    recordSyncFailure
} = require('../advisories/state');

const {
    resolveEditorRegistry,
    loadExtensionProvenance,
    isRegistryAndPlatformMatch
} = require('../advisories/registry');

const {
    toAdvisoryEntry,
    mergeAdvisories,
    fetchPkgscanAdvisories
} = require('../advisories/sync');

test('pointer advances only on success and never on failure', () => {
    const start = defaultSyncState();
    const now = Date.parse('2026-10-30T16:00:00.000Z');
    const items = [
        { id: 'adv-1', updatedAt: '2026-10-30T15:00:00.000Z' },
        { id: 'adv-2', updatedAt: '2026-10-30T15:35:00.000Z' }
    ];

    const afterSuccess = recordSyncSuccess(start, { items, full: true, etag: '"v1"', minWaitMs: 300000, now });
    assert.deepEqual(afterSuccess.pointer, { updatedAt: '2026-10-30T15:35:00.000Z', id: 'adv-2' });
    assert.equal(afterSuccess.failureCount, 0);
    assert.equal(afterSuccess.etag, '"v1"');

    // A failed poll increments failureCount but leaves pointer and timestamps intact.
    const afterFailure = recordSyncFailure(afterSuccess);
    assert.deepEqual(afterFailure.pointer, afterSuccess.pointer);
    assert.equal(afterFailure.lastSuccessAt, now);
    assert.equal(afterFailure.failureCount, 1);
});

test('10-minute overlap window and corrupt-state / long-gap full resync', () => {
    const pointer = { updatedAt: '2026-10-30T15:30:00.000Z', id: 'adv-2' };
    // 5 minutes older than pointer is still inside the 10-minute overlap -> keep reading.
    assert.equal(hasReachedPointer({ updatedAt: '2026-10-30T15:25:00.000Z' }, pointer), false);
    // 10 minutes older reaches the cutoff -> stop reading.
    const atCutoff = new Date(Date.parse(pointer.updatedAt) - OVERLAP_MS).toISOString();
    assert.equal(hasReachedPointer({ updatedAt: atCutoff }, pointer), true);

    // Corrupt globalState falls back to default state and forces a full resync.
    const badContext = { globalState: { get: () => ({ pointer: { updatedAt: 'not-a-date', id: '' }, failureCount: -5 }) } };
    const loaded = loadSyncState(badContext);
    assert.equal(loaded.pointer, null);
    assert.equal(shouldForceFullSync(loaded, Date.now(), true), true);

    // Gap > 14 days or > 24h since full sync forces full resync.
    const now = Date.parse('2026-10-30T16:00:00.000Z');
    const freshState = { pointer, lastSuccessAt: now - 1000, lastFullSyncAt: now - 1000, etag: null, minWaitMs: 0, failureCount: 0 };
    assert.equal(shouldForceFullSync(freshState, now, true), false);
    assert.equal(shouldForceFullSync({ ...freshState, lastSuccessAt: now - MAX_GAP_MS - 1 }, now, true), true);
    assert.equal(shouldForceFullSync({ ...freshState, lastFullSyncAt: now - FULL_SYNC_INTERVAL_MS - 1 }, now, true), true);
});

test('registry mapping per editor and provenance matching (gallery vs vsix, REMOVED kept)', () => {
    const cursorReg = resolveEditorRegistry({
        appRoot: '/fake/cursor',
        readFileSync: () => JSON.stringify({ extensionsGallery: { serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery' } })
    });
    assert.equal(cursorReg.registry, 'cursor-marketplace');

    const vscodeReg = resolveEditorRegistry({ appName: 'Visual Studio Code' });
    assert.equal(vscodeReg.registry, 'vscode-marketplace');

    const codiumReg = resolveEditorRegistry({ appName: 'VSCodium' });
    assert.equal(codiumReg.registry, 'openvsx');

    // Load provenance from extensions.json.
    const exts = [
        { id: 'pub.gallery-ext', extensionPath: '/ext/pub.gallery-ext-1.0.0' },
        { id: 'pub.sideloaded-ext', extensionPath: '/ext/pub.sideloaded-ext-1.0.0' }
    ];
    const prov = loadExtensionProvenance(exts, {
        readFileSync: () => JSON.stringify([
            { identifier: { id: 'pub.gallery-ext' }, metadata: { source: 'gallery', targetPlatform: 'universal' } },
            { identifier: { id: 'pub.sideloaded-ext' }, metadata: { source: 'vsix', targetPlatform: 'win32-x64' } }
        ])
    });

    const cursorAdvisory = toAdvisoryEntry({
        id: 'cursor-marketplace:pub.gallery-ext@1.0.0:universal',
        ecosystem: 'vscode-extension',
        registry: 'cursor-marketplace',
        namespace: 'pub',
        name: 'gallery-ext',
        version: '1.0.0',
        platform: 'universal',
        severity: 'critical',
        windows: [{ state: 'REMOVED', takenDownAt: '2026-10-29T20:35:00.000Z' }]
    });

    // REMOVED advisory is still kept and retains its takedown timestamp.
    assert.equal(cursorAdvisory.windowState, 'REMOVED');
    assert.equal(cursorAdvisory.takenDownAt, '2026-10-29T20:35:00.000Z');

    // Wrong registry is ignored for a gallery extension in VS Code, but matches in Cursor.
    assert.equal(isRegistryAndPlatformMatch(cursorAdvisory, exts[0], prov.get('pub.gallery-ext'), 'vscode-marketplace'), false);
    assert.equal(isRegistryAndPlatformMatch(cursorAdvisory, exts[0], prov.get('pub.gallery-ext'), 'cursor-marketplace'), true);

    // Sideloaded VSIX extension matches advisories from any registry, unless platform conflicts.
    assert.equal(isRegistryAndPlatformMatch(cursorAdvisory, exts[1], prov.get('pub.sideloaded-ext'), 'vscode-marketplace'), true);
    assert.equal(isRegistryAndPlatformMatch({ ...cursorAdvisory, platform: 'darwin-arm64' }, exts[1], prov.get('pub.sideloaded-ext'), 'vscode-marketplace'), false);
});

test('mergeAdvisories de-duplicates by ID and drops withdrawn advisories, and ETag 304 works', async () => {
    const existing = [
        { id: 'adv-1', extensionId: 'a.b', version: '1.0.0', severity: 'medium' },
        { id: 'adv-2', extensionId: 'c.d', version: '1.0.0', severity: 'high' }
    ];
    const fresh = [
        { id: 'adv-1', extensionId: 'a.b', version: '1.0.0', severity: 'critical' },
        { id: 'adv-2', extensionId: 'c.d', version: '1.0.0', withdrawn: true }
    ];
    const merged = mergeAdvisories(existing, fresh);
    assert.equal(merged.length, 1);
    assert.equal(merged[0].id, 'adv-1');
    assert.equal(merged[0].severity, 'critical');

    // Verify ETag 304 Not Modified path sends If-None-Match and parses X-Min-Poll-Seconds.
    let seenHeaders = null;
    const res304 = await fetchPkgscanAdvisories({
        pointer: { updatedAt: '2026-10-30T15:00:00.000Z', id: 'adv-1' },
        full: false,
        etag: '"etag-123"',
        fetchImpl: async (_url, opts) => {
            seenHeaders = opts.headers;
            return {
                status: 304,
                ok: false,
                headers: new Map([['etag', '"etag-123"'], ['x-min-poll-seconds', '420']])
            };
        }
    });
    assert.equal(seenHeaders['if-none-match'], '"etag-123"');
    assert.equal(res304.notModified, true);
    assert.equal(res304.minWaitMs, 420000);
});
