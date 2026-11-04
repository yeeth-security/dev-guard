/**
 * Unit and integration tests for the local marketplace security proxy:
 *   - `advisories/registry.js` (`resolveEditorGalleryUrl`)
 *   - `proxy/config.js` (state persistence, setting update, and restore)
 *   - `proxy/readme.js` (pkgscan.dev scan summary and advisory header injection)
 *   - `proxy/server.js` & `proxy/index.js` (end-to-end HTTP proxy: query rewriting,
 *     README injection, 403 VSIX download blocking, allowlist bypass, and lifecycle)
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { resolveEditorGalleryUrl } = require('../advisories/registry');
const {
    resolveDefaultProxyPort,
    isLoopbackUrl,
    buildProxyServiceUrl,
    restoreProductJsonGallery,
    resolveUpstreamMarketplace,
    applyProxyMarketplaceConfig,
    restoreProxyMarketplaceConfig
} = require('../proxy/config');
const { ASSET_README, ASSET_MANIFEST, ASSET_VSIX, createMarketplaceProxy } = require('../proxy/server');
const { buildPkgscanUrls, resolveRepositoryUrl, formatScanHeader, collectEngineThreats } = require('../proxy/readme');
const {
    writeUninstallRestoreManifest,
    createSelfUninstallDetector,
    restoreMarketplaceSettingsFile,
    runUninstallRestore
} = require('../proxy/uninstall');
const { createProxyController } = require('../proxy');
const { createAuditLog } = require('../audit');
const { signAssetBase, computeHandshakeMac, decodeAndVerifyAssetBase, isAllowedAssetBaseUrl } = require('../proxy/security');

// Fixed secret for tests that build `/asset/` URLs by hand.
// The proxy rejects unsigned asset URLs, so tests must sign them like the proxy does.
const TEST_SECRET = '1'.repeat(64);

/** Builds a signed `/asset/<sig>.<base>/<publisher>/<name>/<version>/<platform>` path segment. */
function signedAssetPath(decodedBase, publisher, name, version, platform = 'universal', secret = TEST_SECRET) {
    const enc = signAssetBase(secret, { decodedBase, publisher, name, version, platform });
    return `${enc}/${publisher}/${name}/${version}/${platform}`;
}

function createFakeEnv(initialSettings = {}) {
    const store = new Map();
    const settings = {
        'extensions.gallery.serviceUrl': initialSettings.galleryServiceUrl ?? '',
        'devGuard.marketplace': initialSettings.marketplace ?? '',
        'devGuard.proxy.enabled': initialSettings.proxyEnabled ?? true,
        'devGuard.allowlist': initialSettings.allowlist ?? []
    };
    const warnings = [];
    const context = {
        globalState: {
            get: k => store.get(k),
            update: async (k, v) => { store.set(k, v); }
        }
    };
    const vscodeApi = {
        ConfigurationTarget: { Global: 1 },
        env: { appName: 'Cursor', appRoot: '/nonexistent' },
        commands: { executeCommand: async () => {} },
        Uri: { parse: u => u },
        window: {
            showWarningMessage: (msg, ...btns) => {
                warnings.push({ msg, btns });
                return Promise.resolve(undefined);
            }
        },
        workspace: {
            getConfiguration: section => ({
                get: (key, fallback) => {
                    const full = `${section}.${key}`;
                    return full in settings && settings[full] !== undefined ? settings[full] : fallback;
                },
                update: async (key, value) => {
                    settings[`${section}.${key}`] = value;
                }
            })
        }
    };
    return { context, vscodeApi, settings, warnings };
}

function startMockServer(handler) {
    return new Promise(resolve => {
        const srv = http.createServer(handler);
        srv.listen(0, '127.0.0.1', () => {
            const port = srv.address().port;
            resolve({
                url: `http://127.0.0.1:${port}`,
                close: () => new Promise(r => srv.close(() => r()))
            });
        });
    });
}

test('resolveEditorGalleryUrl reads product.json or falls back to editor default', () => {
    const fromProduct = resolveEditorGalleryUrl({
        appRoot: '/app',
        readFileSync: () => JSON.stringify({
            extensionsGallery: { serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery/' }
        })
    });
    assert.equal(fromProduct.serviceUrl, 'https://marketplace.cursorapi.com/_apis/public/gallery');
    assert.equal(fromProduct.registry, 'cursor-marketplace');

    const fallback = resolveEditorGalleryUrl({ appName: 'VSCodium' });
    assert.equal(fallback.serviceUrl, 'https://open-vsx.org/vscode/gallery');
    assert.equal(fallback.registry, 'openvsx');
});

test('proxy config updates marketplace to local proxy and restores original settings when turned off', async () => {
    const { context, vscodeApi, settings } = createFakeEnv({
        galleryServiceUrl: 'https://open-vsx.org/vscode/gallery',
        marketplace: 'https://open-vsx.org/vscode/gallery'
    });

    const upstreamBefore = resolveUpstreamMarketplace(context, vscodeApi);
    assert.equal(upstreamBefore.serviceUrl, 'https://open-vsx.org/vscode/gallery');
    assert.equal(upstreamBefore.registry, 'openvsx');

    await applyProxyMarketplaceConfig(context, vscodeApi, 45821, upstreamBefore.serviceUrl);
    const expectedProxyUrl = buildProxyServiceUrl(45821);
    assert.equal(settings['extensions.gallery.serviceUrl'], expectedProxyUrl);
    assert.equal(settings['devGuard.marketplace'], expectedProxyUrl);
    assert.equal(isLoopbackUrl(expectedProxyUrl), true);

    // While proxy is active, resolveUpstreamMarketplace still returns the saved real upstream.
    const upstreamDuring = resolveUpstreamMarketplace(context, vscodeApi);
    assert.equal(upstreamDuring.serviceUrl, 'https://open-vsx.org/vscode/gallery');

    // Turning off restores the exact prior URLs.
    await restoreProxyMarketplaceConfig(context, vscodeApi);
    assert.equal(settings['extensions.gallery.serviceUrl'], 'https://open-vsx.org/vscode/gallery');
    assert.equal(settings['devGuard.marketplace'], 'https://open-vsx.org/vscode/gallery');
});

test('revoking an allowlisted engine-scan package produces a live finding', async () => {
    const ext = { id: 'AckeeBlockchain.tools-for-solidity', packageJSON: { version: '1.19.4' } };
    const scan = {
        status: 'completed',
        flaggedCount: 1,
        engines: [{ id: 'guarddog', verdict: 'block', findingCount: 16 }]
    };
    const { threats, retry } = await collectEngineThreats({
        ids: ['ackeeblockchain.tools-for-solidity'],
        extensions: [ext],
        allowlist: new Set(),
        skipIds: new Set(),
        registry: 'cursor-marketplace',
        getScanData: async () => scan
    });
    assert.equal(retry.length, 0);
    assert.equal(threats.length, 1);
    assert.equal(threats[0].extension, ext);
    assert.match(threats[0].advisory.title, /guarddog/);

    // Still allowlisted, or already matched by the advisory feed: no second finding.
    const quiet = await collectEngineThreats({
        ids: ['ackeeblockchain.tools-for-solidity'],
        extensions: [ext],
        allowlist: new Set(['ackeeblockchain.tools-for-solidity']),
        skipIds: new Set(),
        getScanData: async () => scan
    });
    assert.equal(quiet.threats.length, 0);
});

test('README injection is a GitHub alert without START/END headings', () => {
    const clean = formatScanHeader({
        publisher: 'good', name: 'clean-ext', version: '1.0.0',
        scan: { status: 'completed', flaggedCount: 0, analyzedAt: '2026-11-01', engines: [{ id: 'argus', verdict: 'pass', status: 'done', findingCount: 0 }] }
    });
    assert.ok(clean.includes('It is **not** part of the publisher\'s README.'));
    assert.ok(clean.includes('The publisher\'s original README starts below this line.'));
    assert.ok(clean.includes('[!NOTE]'), 'a finished clean scan is a note alert');
    assert.ok(!clean.includes('START of injected scan data'));
    assert.ok(!clean.includes('END of injected scan data'));

    const flagged = formatScanHeader({
        publisher: 'evil', name: 'bad-ext', version: '9.9.9',
        advisory: { severity: 'critical', title: 'TOKEN_STEALER', permalink: 'https://www.pkgscan.dev/x' }
    });
    assert.ok(flagged.includes('[DEV-GUARD SECURITY ADVISORY — CRITICAL]'));
    assert.ok(flagged.includes('[!CAUTION]'), 'a flagged extension is a caution alert');
    assert.ok(flagged.includes('> > [!CAUTION]'), 'the advisory is its own box inside the scan alert');
    assert.ok(!flagged.includes('START of injected scan data'));
    assert.ok(!flagged.includes('END of injected scan data'));
});

test('proxy rewrites extensionquery, injects scan data into README, and blocks flagged VSIX downloads', async () => {
    const mockUpstream = await startMockServer((req, res) => {
        const origin = `http://127.0.0.1:${req.socket.localPort}`;
        if (req.url.endsWith('/extensionquery')) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
                results: [{
                    extensions: [
                        {
                            publisher: { publisherName: 'good' },
                            extensionName: 'clean-ext',
                            versions: [{
                                version: '1.0.0',
                                targetPlatform: 'universal',
                                assetUri: `${origin}/upstream-assets/good/clean-ext/1.0.0`,
                                fallbackAssetUri: `${origin}/upstream-assets/good/clean-ext/1.0.0`,
                                files: [
                                    { assetType: 'Microsoft.VisualStudio.Services.Icons.Default', source: `${origin}/upstream-assets/good/clean-ext/1.0.0/icon` },
                                    { assetType: ASSET_README, source: `${origin}/upstream-assets/good/clean-ext/1.0.0/${ASSET_README}` }
                                ]
                            }]
                        },
                        {
                            publisher: { publisherName: 'evil' },
                            extensionName: 'bad-ext',
                            versions: [{
                                version: '0.1.2',
                                targetPlatform: 'universal',
                                assetUri: `${origin}/upstream-assets/evil/bad-ext/0.1.2`,
                                fallbackAssetUri: `${origin}/upstream-assets/evil/bad-ext/0.1.2`,
                                files: [{ assetType: ASSET_VSIX, source: `${origin}/upstream-assets/evil/bad-ext/0.1.2/${ASSET_VSIX}` }]
                            }]
                        }
                    ]
                }]
            }));
            return;
        }
        if (req.url.endsWith(`/${ASSET_README}`)) {
            res.writeHead(200, { 'content-type': 'text/markdown' });
            res.end('# Original Extension Readme\nHello world!');
            return;
        }
        if (req.url.endsWith(`/${ASSET_VSIX}`)) {
            res.writeHead(200, { 'content-type': 'application/octet-stream' });
            res.end('FAKE-VSIX-BINARY');
            return;
        }
        res.writeHead(404);
        res.end();
    });

    const mockPkgscan = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
            status: 'completed',
            flaggedCount: 0,
            analyzedAt: '2026-10-31T21:50:26.705Z',
            sha256: '7b6afc047260e4d9fc8d9adf5222304dca62ed69b9e43780d63f765503893d57',
            extension: { publisher: 'good', name: 'clean-ext', version: '1.0.0' },
            engines: [
                { id: 'argus', status: 'done', verdict: 'pass', findingCount: 0 },
                { id: 'guarddog', status: 'done', verdict: 'warn', findingCount: 2 }
            ]
        }));
    });

    const allowlist = new Set();
    const blockedEvents = [];
    const advisories = [{
        id: 'adv-evil',
        extensionId: 'evil.bad-ext',
        version: '0.1.2',
        severity: 'critical',
        title: 'CREDENTIAL_STEALER',
        permalink: 'https://www.pkgscan.dev/pkg/vscode-extension/evil/bad-ext@0.1.2'
    }];

    const proxy = createMarketplaceProxy({
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: `${mockUpstream.url}/_apis/public/gallery`, registry: 'openvsx' }),
        getAdvisories: () => advisories,
        isAllowlisted: id => allowlist.has(id.toLowerCase()),
        onBlockedDownload: info => blockedEvents.push(info),
        pkgscanBaseUrl: mockPkgscan.url
    });

    const port = await proxy.start(0);
    try {
        const proxyGallery = `http://127.0.0.1:${port}/_apis/public/gallery`;

        // 0. Browser CORS preflight (OPTIONS) from `vscode-file://vscode-app` succeeds with 204 and allows custom headers.
        const preflight = await fetch(`${proxyGallery}/extensionquery`, {
            method: 'OPTIONS',
            headers: {
                Origin: 'vscode-file://vscode-app',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'content-type,vscode-sessionid,x-market-client-id,x-market-user-id,x-og-device-group'
            }
        });
        assert.equal(preflight.status, 204);
        assert.equal(preflight.headers.get('access-control-allow-origin'), 'vscode-file://vscode-app');
        assert.ok(preflight.headers.get('access-control-allow-methods').includes('POST'));
        assert.ok(preflight.headers.get('access-control-allow-headers').includes('x-market-client-id'));

        // 1. Query extensions: both clean and flagged extensions still appear in results.
        const qRes = await fetch(`${proxyGallery}/extensionquery`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ filters: [] })
        });
        assert.equal(qRes.status, 200);
        const qData = await qRes.json();
        const [cleanExt, badExt] = qData.results[0].extensions;
        assert.equal(cleanExt.extensionName, 'clean-ext');
        assert.equal(badExt.extensionName, 'bad-ext');

        // Clean extension: assetUri points to proxy, fallbackAssetUri stays on upstream so marketplace icons load.
        assert.ok(cleanExt.versions[0].assetUri.startsWith(`http://127.0.0.1:${port}/asset/`));
        assert.ok(cleanExt.versions[0].fallbackAssetUri.startsWith(mockUpstream.url));

        // Flagged extension (without icon): both assetUri and fallbackAssetUri point to proxy.
        assert.ok(badExt.versions[0].assetUri.startsWith(`http://127.0.0.1:${port}/asset/`));
        assert.ok(badExt.versions[0].fallbackAssetUri.startsWith(`http://127.0.0.1:${port}/asset/`));

        // 2. Fetch README for clean extension: scan table + original README present.
        const cleanReadmeRes = await fetch(`${cleanExt.versions[0].assetUri}/${ASSET_README}`);
        const cleanReadme = await cleanReadmeRes.text();
        assert.ok(cleanReadme.includes('**pkgscan.dev Security Scan** — **No malware engines flagged**'));
        assert.ok(cleanReadme.includes('| `argus` | Clean (pass) | 0 |'));
        assert.ok(!cleanReadme.includes('START of injected scan data'));
        assert.ok(!cleanReadme.includes('END of injected scan data'));
        assert.ok(cleanReadme.includes('[!NOTE]'));
        assert.ok(cleanReadme.includes('# Original Extension Readme'));

        // 3. Fetch README for flagged extension: advisory banner injected at the top.
        const badReadmeRes = await fetch(`${badExt.versions[0].assetUri}/${ASSET_README}`);
        const badReadme = await badReadmeRes.text();
        assert.ok(badReadme.includes('[DEV-GUARD SECURITY ADVISORY — CRITICAL]'));
        assert.ok(badReadme.includes('[!CAUTION]'));
        assert.ok(badReadme.includes('Download blocked by Dev-Guard.'));

        // 4. Attempt VSIX download for flagged extension -> HTTP 403 Forbidden.
        const blockedVsix = await fetch(`${badExt.versions[0].fallbackAssetUri}/${ASSET_VSIX}`);
        assert.equal(blockedVsix.status, 403);
        assert.equal(blockedEvents.length, 1);
        assert.equal(blockedEvents[0].id, 'evil.bad-ext');

        // 5. Allowlisting the extension permits the VSIX download -> HTTP 200 OK.
        allowlist.add('evil.bad-ext');
        const allowedVsix = await fetch(`${badExt.versions[0].fallbackAssetUri}/${ASSET_VSIX}`);
        assert.equal(allowedVsix.status, 200);
        assert.equal(await allowedVsix.text(), 'FAKE-VSIX-BINARY');
    } finally {
        await proxy.stop();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('createProxyController toggles proxy on/off, prompts to restart IDE, and restores settings cleanly', async () => {
    const { context, vscodeApi, settings, warnings } = createFakeEnv({
        galleryServiceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery',
        marketplace: ''
    });
    const audit = createAuditLog(context);
    const controller = createProxyController({
        context,
        vscodeApi,
        getAdvisories: () => [],
        audit
    });

    try {
        await controller.sync();
        assert.equal(controller.isRunning(), true);
        assert.equal(controller.getStatus().proxyNeedsRestart, true, 'first install marks proxyNeedsRestart until IDE restarts');
        assert.equal(warnings.length, 1, 'prompts user to restart IDE when proxy is configured');
        assert.match(warnings[0].msg, /Restart the IDE/);
        assert.ok(warnings[0].btns.includes('Restart Now'));
        const port = controller.getPort();
        assert.equal(settings['extensions.gallery.serviceUrl'], buildProxyServiceUrl(port));
        assert.equal(settings['devGuard.marketplace'], buildProxyServiceUrl(port));

        await controller.setEnabled(false, 'panel');
        assert.equal(controller.isRunning(), false);
        assert.equal(controller.getStatus().proxyNeedsRestart, false);
        assert.equal(warnings.length, 2, 'prompts user to restart IDE when proxy is disabled');
        assert.match(warnings[1].msg, /Restart the IDE/);
        assert.equal(settings['extensions.gallery.serviceUrl'], 'https://marketplace.cursorapi.com/_apis/public/gallery');
        assert.equal(settings['devGuard.marketplace'], '');
        assert.equal(audit.list()[0].type, 'proxy');
    } finally {
        controller.dispose();
    }
});

test('second window sharing an in-use proxy port keeps the same port without changing settings', async () => {
    const proxy1 = createMarketplaceProxy({
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => []
    });
    const proxy2 = createMarketplaceProxy({
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => []
    });

    try {
        const port1 = await proxy1.start(0);
        // Simulate a second Cursor window starting while the first window already holds `port1`.
        const port2 = await proxy2.start(port1);
        assert.equal(port2, port1, 'second window must keep the same port instead of picking a random port');
        assert.equal(proxy2.isRunning(), true);
    } finally {
        await proxy2.stop();
        await proxy1.stop();
    }
});

test('install of extension flagged by pkgscan engine verdict is blocked at manifest/VSIX check and opens allowlist modal', async () => {
    const mockPkgscan = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
            status: 'completed',
            flaggedCount: 1,
            permalink: '/pkg/vscode-extension/ackeeblockchain/tools-for-solidity@1.19.4',
            engines: [{ id: 'guarddog', status: 'done', verdict: 'block', findingCount: 16 }]
        }));
    });

    const { context, vscodeApi, settings, warnings } = createFakeEnv();
    // Simulate user clicking "Allowlist Extension" in the modal dialog.
    vscodeApi.window.showWarningMessage = (msg, opts, ...btns) => {
        warnings.push({ msg, opts, btns });
        const allowBtn = btns.find(b => b && b.title === 'Allowlist Extension');
        return Promise.resolve(allowBtn);
    };

    let blockedInfo = null;
    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        isAllowlisted: id => (settings['devGuard.allowlist'] || []).includes(id.toLowerCase()),
        onBlockedDownload: info => {
            blockedInfo = info;
            vscodeApi.window.showWarningMessage(
                `Malicious Extension Blocked: ${info.id}@${info.version}`,
                { modal: true, detail: info.advisory.title },
                { title: 'Allowlist Extension' },
                { title: 'Cancel Install', isCloseAffordance: true }
            ).then(sel => {
                if (sel && sel.title === 'Allowlist Extension') {
                    settings['devGuard.allowlist'] = [info.id.toLowerCase()];
                }
            });
        },
        pkgscanBaseUrl: mockPkgscan.url
    });

    const port = await proxy.start(0);
    try {
        const assetPath = signedAssetPath('https://marketplace.cursorapi.com/open-vsx-mirror/vscode/asset/AckeeBlockchain/tools-for-solidity/1.19.4', 'AckeeBlockchain', 'tools-for-solidity', '1.19.4');
        const assetBase = `http://127.0.0.1:${port}/asset/${assetPath}`;

        // 1. Install-time Manifest fetch (no Origin header, from sharedProcess) returns blocked manifest
        // with version `0.0.0-blocked-by-dev-guard` so VS Code aborts without opening a second modal popup.
        const manRes = await fetch(`${assetBase}/${ASSET_MANIFEST}`);
        assert.equal(manRes.status, 200);
        const manJson = await manRes.json();
        assert.equal(manJson.version, '0.0.0-blocked-by-dev-guard');
        assert.equal(blockedInfo.id, 'AckeeBlockchain.tools-for-solidity');
        assert.equal(warnings.length, 1);
        assert.equal(warnings[0].opts.modal, true);
        assert.equal(warnings[0].btns.find(b => b.isCloseAffordance).title, 'Cancel Install');

        // Verify that VS Code's immediate follow-up `getDownloadUrl()` query (`flags: 439` IncludeVersions
        // without IncludeLatestVersionOnly, querying by UUID `filterType: 4`) returns an empty list
        // so it never offers "Try Downloading Manually...".
        const followupRes = await fetch(`http://127.0.0.1:${port}/_apis/public/gallery/extensionquery`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                flags: 439,
                filters: [{ criteria: [{ filterType: 4, value: 'e52ee86d-d1a6-4190-8335-ed4a924b2d99' }] }]
            })
        });
        assert.equal(followupRes.status, 200);
        const followupJson = await followupRes.json();
        assert.deepEqual(followupJson.results[0].extensions, []);

        // 2. After user clicked "Allowlist Extension" in the modal, the extension is allowlisted.
        await new Promise(resolve => setTimeout(resolve, 10));
        assert.deepEqual(settings['devGuard.allowlist'], ['ackeeblockchain.tools-for-solidity']);
    } finally {
        await proxy.stop();
        await mockPkgscan.close();
    }
});

test('Open VSX and Cursor open-vsx-mirror extensions use ?repository_url=https://open-vsx.org in PURL, API, and README links', async () => {
    // 1. Unit checks for resolveRepositoryUrl and buildPkgscanUrls across marketplaces.
    assert.equal(resolveRepositoryUrl({ registry: 'openvsx' }), 'https://open-vsx.org');
    assert.equal(resolveRepositoryUrl({ registry: 'cursor-marketplace' }), 'https://open-vsx.org');
    assert.equal(
        resolveRepositoryUrl({
            registry: 'vscode-marketplace',
            assetBaseUrl: 'https://marketplace.cursorapi.com/open-vsx-mirror/vscode/asset/pub/ext/1.0.0'
        }),
        'https://open-vsx.org'
    );
    assert.equal(
        resolveRepositoryUrl({
            registry: 'cursor-marketplace',
            assetBaseUrl: 'https://pub.gallerycdn.vsassets.io/extensions/pub/ext/1.0.0/asset'
        }),
        null
    );

    const openVsxUrls = buildPkgscanUrls({
        publisher: 'TintinWeb',
        name: 'solidity-visual-auditor',
        version: '0.2.3',
        registry: 'cursor-marketplace',
        assetBaseUrl: 'https://marketplace.cursorapi.com/open-vsx-mirror/vscode/asset/TintinWeb/solidity-visual-auditor/0.2.3'
    });
    assert.equal(
        openVsxUrls.purl,
        'pkg:vscode-extension/tintinweb/solidity-visual-auditor@0.2.3?repository_url=https%3A%2F%2Fopen-vsx.org'
    );
    assert.ok(openVsxUrls.apiUrl.endsWith('?repository_url=https%3A%2F%2Fopen-vsx.org'));
    assert.ok(openVsxUrls.reportUrl.endsWith('?repository_url=https%3A%2F%2Fopen-vsx.org'));
    assert.ok(openVsxUrls.badgeUrl.endsWith('?repository_url=https%3A%2F%2Fopen-vsx.org'));

    const msUrls = buildPkgscanUrls({
        publisher: 'ms-python',
        name: 'python',
        version: '2026.1.0',
        registry: 'vscode-marketplace',
        assetBaseUrl: 'https://ms-python.gallerycdn.vsassets.io/extensions/ms-python/python/2026.1.0/asset'
    });
    assert.equal(msUrls.purl, 'pkg:vscode-extension/ms-python/python@2026.1.0');
    assert.equal(msUrls.reportUrl.includes('repository_url'), false);

    // 2. Integration check: README injection for an unscanned Open VSX extension never falls back
    // to the unscoped Microsoft Marketplace query and injects the Open VSX PURL + reportUrl.
    const requestedUrls = [];
    const mockPkgscan = await startMockServer((req, res) => {
        requestedUrls.push(req.url);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'unscanned' }));
    });
    const mockUpstream = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'text/markdown' });
        res.end('# Open VSX Extension');
    });

    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        pkgscanBaseUrl: mockPkgscan.url
    });

    const port = await proxy.start(0);
    try {
        const assetPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/TintinWeb/solidity-visual-auditor/0.2.3`, 'TintinWeb', 'solidity-visual-auditor', '0.2.3');
        const readmeRes = await fetch(`http://127.0.0.1:${port}/asset/${assetPath}/${ASSET_README}`);
        const readmeText = await readmeRes.text();

        // Every pkgscan API request must carry ?repository_url=https%3A%2F%2Fopen-vsx.org
        assert.ok(requestedUrls.length >= 1);
        for (const reqUrl of requestedUrls) {
            assert.ok(
                reqUrl.includes('repository_url=https%3A%2F%2Fopen-vsx.org'),
                `Expected Open VSX repository_url in pkgscan API call, got: ${reqUrl}`
            );
        }

        assert.ok(readmeText.includes('pkg:vscode-extension/tintinweb/solidity-visual-auditor@0.2.3?repository_url=https%3A%2F%2Fopen-vsx.org'));
        assert.ok(readmeText.includes('/pkg/vscode-extension/tintinweb/solidity-visual-auditor@0.2.3?repository_url=https%3A%2F%2Fopen-vsx.org'));
    } finally {
        await proxy.stop();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('viewing an unscanned extension README does not cache unscanned status, so installing after scanning immediately blocks', async () => {
    let scanCompleted = false;
    const mockPkgscan = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        if (!scanCompleted) {
            res.end(JSON.stringify({ status: 'unscanned' }));
            return;
        }
        res.end(JSON.stringify({
            status: 'completed',
            flaggedCount: 1,
            engines: [{ id: 'guarddog', status: 'done', verdict: 'block', findingCount: 16 }]
        }));
    });
    const mockUpstream = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'text/markdown' });
        res.end('# Extension Readme');
    });

    const blocked = [];
    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        onBlockedDownload: info => blocked.push(info),
        pkgscanBaseUrl: mockPkgscan.url
    });

    const port = await proxy.start(0);
    try {
        const assetPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/AckeeBlockchain/tools-for-solidity/1.19.4`, 'AckeeBlockchain', 'tools-for-solidity', '1.19.4');
        const assetBase = `http://127.0.0.1:${port}/asset/${assetPath}`;

        // 1. User opens the extension README while it is still `unscanned` on pkgscan.dev.
        const readme1 = await fetch(`${assetBase}/${ASSET_README}`).then(r => r.text());
        assert.ok(readme1.includes('Scan status: `unscanned`'));

        // 2. User scans the extension on pkgscan.dev (status becomes `completed` with `guarddog: block`),
        // then immediately clicks Install in Cursor within seconds.
        scanCompleted = true;
        const vsixRes = await fetch(`${assetBase}/${ASSET_VSIX}`);
        assert.equal(vsixRes.status, 403);
        assert.equal(blocked.length, 1);
        assert.equal(blocked[0].id, 'AckeeBlockchain.tools-for-solidity');
    } finally {
        await proxy.stop();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('unscanned extension install prompts user to Scan on pkgscan.dev or Continue Install at their own risk', async () => {
    const mockPkgscan = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'unscanned' }));
    });
    const mockUpstream = await startMockServer((req, res) => {
        if (req.url.endsWith(`/${ASSET_MANIFEST}`)) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ name: 'unscanned-ext', publisher: 'acme', version: '2.1.0', engines: { vscode: '^1.80.0' } }));
            return;
        }
        if (req.url.endsWith(`/${ASSET_VSIX}`)) {
            res.writeHead(200, { 'content-type': 'application/octet-stream' });
            res.end('UNSCANNED-VSIX-BINARY');
            return;
        }
        res.writeHead(404);
        res.end();
    });

    const prompts = [];
    const openedUrls = [];
    let nextChoice = 'Scan on pkgscan.dev';

    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        onUnscannedInstall: async ({ id, version, reportUrl }) => {
            prompts.push({ id, version, reportUrl });
            if (nextChoice === 'Scan on pkgscan.dev') {
                openedUrls.push(reportUrl);
                return 'scan';
            }
            if (nextChoice === 'Continue Install (At Your Own Risk)') {
                return 'continue';
            }
            return 'cancel';
        },
        pkgscanBaseUrl: mockPkgscan.url
    });

    const port = await proxy.start(0);
    try {
        const assetPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/acme/unscanned-ext/2.1.0`, 'acme', 'unscanned-ext', '2.1.0');
        const assetBase = `http://127.0.0.1:${port}/asset/${assetPath}`;

        // 1. User tries to install unscanned extension and chooses "Scan on pkgscan.dev":
        //    - Opens pkgscan.dev scan URL with Open VSX repository_url
        //    - Aborts the install with blocked manifest
        const manBlocked = await fetch(`${assetBase}/${ASSET_MANIFEST}`).then(r => r.json());
        assert.equal(manBlocked.version, '0.0.0-blocked-by-dev-guard');
        assert.equal(prompts.length, 1);
        assert.equal(prompts[0].id, 'acme.unscanned-ext');
        assert.equal(prompts[0].version, '2.1.0');
        assert.equal(openedUrls.length, 1);
        assert.ok(openedUrls[0].endsWith('/pkg/vscode-extension/acme/unscanned-ext@2.1.0?repository_url=https%3A%2F%2Fopen-vsx.org'));

        // 2. User tries again and chooses "Continue Install (At Your Own Risk)":
        //    - Immediately serves the real upstream Manifest AND VSIX without prompting a second time.
        nextChoice = 'Continue Install (At Your Own Risk)';
        const manAllowed = await fetch(`${assetBase}/${ASSET_MANIFEST}`).then(r => r.json());
        assert.equal(manAllowed.version, '2.1.0');
        assert.equal(prompts.length, 2);

        const vsixRes = await fetch(`${assetBase}/${ASSET_VSIX}`);
        assert.equal(vsixRes.status, 200);
        assert.equal(await vsixRes.text(), 'UNSCANNED-VSIX-BINARY');
        assert.equal(prompts.length, 2, 'subsequent VSIX download for approved version should not re-prompt');
    } finally {
        await proxy.stop();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('Cursor and VS Code use distinct default proxy ports and VS Code falls back to product.json + workbench.html CSP when extensions.gallery.serviceUrl is locked', async () => {
    const crypto = require('node:crypto');
    // 1. Distinct predefined ports per IDE so running multiple editors simultaneously never collides.
    assert.equal(resolveDefaultProxyPort({ appName: 'Cursor' }), 45821);
    assert.equal(resolveDefaultProxyPort({ appName: 'Visual Studio Code' }), 45822);
    assert.equal(resolveDefaultProxyPort({ appName: 'VSCodium' }), 45823);
    assert.equal(resolveDefaultProxyPort({ appName: 'Windsurf' }), 45824);
    assert.equal(resolveDefaultProxyPort({ appName: 'Visual Studio Code - Insiders' }), 45825);
    assert.equal(resolveDefaultProxyPort({ appName: 'Positron' }), 45826);

    // 2. Simulate VS Code 1.144+ where `extensions.gallery.serviceUrl` throws because `included: false`
    //    and `workbench.html` only has `connect-src 'self' https: ws:;`.
    const origWorkbenchHtml = [
        '<meta http-equiv="Content-Security-Policy" content="',
        "\t\t\t\timg-src\r\n\t\t\t\t\t'self'\r\n\t\t\t\t\thttps:\r\n\t\t\t\t;",
        "\t\t\t\tframe-src\r\n\t\t\t\t\t'self'\r\n\t\t\t\t\tvscode-webview:\r\n\t\t\t\t;",
        "\t\t\t\tconnect-src\r\n\t\t\t\t\t'self'\r\n\t\t\t\t\thttps:\r\n\t\t\t\t\tws:\r\n\t\t\t\t;",
        '"/>'
    ].join('\r\n');
    const origHtmlChecksum = crypto.createHash('sha256').update(Buffer.from(origWorkbenchHtml, 'utf8')).digest('base64').replace(/=+$/, '');
    let workbenchHtmlText = origWorkbenchHtml;
    let productJsonText = JSON.stringify({
        extensionsGallery: {
            serviceUrl: 'https://marketplace.visualstudio.com/_apis/public/gallery',
            extensionUrlTemplate: 'https://www.vscode-unpkg.net/_gallery/{publisher}/{name}/latest'
        },
        checksums: {
            'vs/code/electron-browser/workbench/workbench.html': origHtmlChecksum
        }
    });
    const { context, vscodeApi, settings } = createFakeEnv();
    vscodeApi.env = {
        appName: 'Visual Studio Code',
        appRoot: '/vscode-app',
        readFileSync: p => {
            if (String(p).endsWith('product.json')) return productJsonText;
            if (String(p).includes('electron-browser') && String(p).endsWith('workbench.html')) return workbenchHtmlText;
            throw new Error(`ENOENT: ${p}`);
        },
        writeFileSync: (p, data) => {
            if (String(p).endsWith('product.json')) productJsonText = data;
            else if (String(p).endsWith('workbench.html')) workbenchHtmlText = data;
        }
    };
    const origGetConfig = vscodeApi.workspace.getConfiguration;
    vscodeApi.workspace.getConfiguration = section => {
        const base = origGetConfig(section);
        if (section === 'extensions.gallery') {
            return {
                ...base,
                update: async () => {
                    throw new Error('Unable to write to User Settings because extensions.gallery.serviceUrl is not a registered configuration.');
                }
            };
        }
        return base;
    };

    const applied = await applyProxyMarketplaceConfig(
        context,
        vscodeApi,
        45822,
        'https://marketplace.visualstudio.com/_apis/public/gallery'
    );
    assert.equal(applied.productJsonChanged, true);
    assert.equal(settings['devGuard.marketplace'], 'http://127.0.0.1:45822/_apis/public/gallery');

    const patched = JSON.parse(productJsonText);
    assert.equal(patched.extensionsGallery.serviceUrl, 'http://127.0.0.1:45822/_apis/public/gallery');
    assert.equal(
        patched.extensionsGallery.extensionUrlTemplate,
        'http://127.0.0.1:45822/_apis/public/gallery/vscode/{publisher}/{name}/latest'
    );
    assert.ok(workbenchHtmlText.includes('http://127.0.0.1:*'), 'workbench.html CSP allows loopback HTTP proxy');
    const patchedHtmlChecksum = crypto.createHash('sha256').update(Buffer.from(workbenchHtmlText, 'utf8')).digest('base64').replace(/=+$/, '');
    assert.equal(patched.checksums['vs/code/electron-browser/workbench/workbench.html'], patchedHtmlChecksum);

    // Even while product.json is patched to 127.0.0.1, resolveEditorGalleryUrl still returns the real upstream.
    const resolvedDuring = resolveEditorGalleryUrl(vscodeApi.env);
    assert.equal(resolvedDuring.serviceUrl, 'https://marketplace.visualstudio.com/_apis/public/gallery');
    assert.equal(resolvedDuring.registry, 'vscode-marketplace');

    // Turning off the proxy restores product.json AND workbench.html (and its checksum) byte-for-byte.
    await restoreProxyMarketplaceConfig(context, vscodeApi);
    const restored = JSON.parse(productJsonText);
    assert.equal(restored.extensionsGallery.serviceUrl, 'https://marketplace.visualstudio.com/_apis/public/gallery');
    assert.equal(
        restored.extensionsGallery.extensionUrlTemplate,
        'https://www.vscode-unpkg.net/_gallery/{publisher}/{name}/latest'
    );
    assert.equal(restored.extensionsGallery._devGuardOriginalServiceUrl, undefined);
    assert.equal(workbenchHtmlText, origWorkbenchHtml, 'workbench.html restored byte-for-byte');
    assert.equal(restored.checksums['vs/code/electron-browser/workbench/workbench.html'], origHtmlChecksum);
});

test('proxy controller records telemetry for flagged README views, blocked downloads, modal decisions, unscanned refusals, and pkgscan clicks', async () => {
    const mockPkgscan = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        if (req.url.includes('unscanned-ext')) {
            res.end(JSON.stringify({ status: 'unscanned' }));
            return;
        }
        res.end(JSON.stringify({
            status: 'completed',
            flaggedCount: 1,
            engines: [{ id: 'guarddog', status: 'done', verdict: 'block', findingCount: 9 }]
        }));
    });
    const mockUpstream = await startMockServer((req, res) => {
        res.writeHead(200, { 'content-type': 'text/markdown' });
        res.end('# Extension README');
    });

    const telemetryEvents = [];
    const openedUrls = [];
    let nextModalSelection = 'View Report';
    const { context, vscodeApi } = createFakeEnv({
        galleryServiceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery'
    });
    vscodeApi.env.openExternal = uri => { openedUrls.push(uri); return Promise.resolve(true); };
    vscodeApi.window.showWarningMessage = (_msg, _opts, ...btns) => {
        const match = btns.find(b => b && b.title === nextModalSelection);
        return Promise.resolve(match);
    };

    const telemetry = {
        record: (name, props) => telemetryEvents.push({ name, props }),
        recordState: (_key, name, props) => telemetryEvents.push({ name, props }),
        recordOnce: (_key, name, props) => telemetryEvents.push({ name, props })
    };

    const controller = createProxyController({
        context,
        vscodeApi,
        preferredPort: 0,
        allowLoopbackAssets: true,
        pkgscanBaseUrl: mockPkgscan.url,
        getAdvisories: () => [{
            id: 'adv-1',
            extensionId: 'evil.stealer',
            version: '1.0.0',
            severity: 'critical',
            title: 'TOKEN_STEALER',
            permalink: 'https://www.pkgscan.dev/pkg/vscode-extension/evil/stealer@1.0.0'
        }],
        telemetry
    });

    try {
        await controller.sync();
        const port = controller.getPort();
        assert.ok(telemetryEvents.some(e => e.name === 'proxy_status' && e.props.enabled === true && e.props.registry === 'cursor-marketplace'));

        // The fake context has no `globalStorageUri`, so the controller's proxy keeps its secret in globalState.
        const controllerSecret = context.globalState.get('devGuard.proxySecret');
        const stealerPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/evil/stealer/1.0.0`, 'evil', 'stealer', '1.0.0', 'universal', controllerSecret);
        const stealerBase = `http://127.0.0.1:${port}/asset/${stealerPath}`;

        // 1. Viewing a flagged README records `flagged_readme_viewed`.
        await fetch(`${stealerBase}/${ASSET_README}`);
        assert.ok(telemetryEvents.some(e =>
            e.name === 'flagged_readme_viewed'
            && e.props.extension_id === 'evil.stealer'
            && e.props.block_source === 'advisory'
        ));

        // 2. Attempting to download a flagged extension records `download_blocked`, `blocked_modal_decision` (`view_report`, `refused_install: true`), and `pkgscan_opened`.
        nextModalSelection = 'View Report';
        await fetch(`${stealerBase}/${ASSET_VSIX}`);
        await new Promise(resolve => setTimeout(resolve, 20));
        assert.ok(telemetryEvents.some(e =>
            e.name === 'download_blocked'
            && e.props.extension_id === 'evil.stealer'
            && e.props.block_source === 'advisory'
            && e.props.registry === 'cursor-marketplace'
        ));
        assert.ok(telemetryEvents.some(e =>
            e.name === 'blocked_modal_decision'
            && e.props.extension_id === 'evil.stealer'
            && e.props.decision === 'view_report'
            && e.props.refused_install === true
        ));
        assert.ok(telemetryEvents.some(e =>
            e.name === 'pkgscan_opened'
            && e.props.source === 'blocked_modal'
            && e.props.extension_id === 'evil.stealer'
        ));

        // 3. Attempting to install an unscanned extension and choosing "Scan on pkgscan.dev" records `unscanned_install_decision` (`refused_install: true`) and `pkgscan_opened`.
        const unscannedPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/acme/unscanned-ext/2.0.0`, 'acme', 'unscanned-ext', '2.0.0', 'universal', controllerSecret);
        const unscannedBase = `http://127.0.0.1:${port}/asset/${unscannedPath}`;
        nextModalSelection = 'Scan on pkgscan.dev';
        await fetch(`${unscannedBase}/${ASSET_MANIFEST}`);
        assert.ok(telemetryEvents.some(e =>
            e.name === 'unscanned_install_decision'
            && e.props.extension_id === 'acme.unscanned-ext'
            && e.props.decision === 'scan'
            && e.props.refused_install === true
            && e.props.scan_status === 'unscanned'
        ));
        assert.ok(telemetryEvents.some(e =>
            e.name === 'pkgscan_opened'
            && e.props.source === 'unscanned_modal'
            && e.props.extension_id === 'acme.unscanned-ext'
        ));

        // 4. Choosing "Cancel Install" on an unscanned extension records `decision: 'cancel'` and `refused_install: true`.
        nextModalSelection = 'Cancel Install';
        await fetch(`${unscannedBase}/${ASSET_MANIFEST}`);
        assert.ok(telemetryEvents.some(e =>
            e.name === 'unscanned_install_decision'
            && e.props.extension_id === 'acme.unscanned-ext'
            && e.props.decision === 'cancel'
            && e.props.refused_install === true
        ));
    } finally {
        controller.dispose();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('uninstall hook and self-uninstall detector revert marketplace settings in settings.json and product.json', async () => {
    const path = require('node:path');
    const files = new Map();
    const norm = p => path.resolve(String(p));
    const fakeIo = {
        mkdirSync: () => {},
        existsSync: p => files.has(norm(p)),
        readFileSync: p => {
            const k = norm(p);
            if (!files.has(k)) throw new Error(`ENOENT: ${k}`);
            return files.get(k);
        },
        writeFileSync: (p, data) => { files.set(norm(p), String(data)); }
    };

    const userDir = norm('/appdata/Code/User');
    const storageDir = path.join(userDir, 'globalStorage', 'yeeth.dev-guard');
    const settingsPath = path.join(userDir, 'settings.json');
    const appRoot = norm('/vscode/resources/app');
    const productPath = path.join(appRoot, 'product.json');
    const extensionsDir = norm('/home/.vscode/extensions');
    const extPath = path.join(extensionsDir, 'yeeth.dev-guard-0.1.3');

    // Simulate active proxy state on disk:
    // - settings.json has `devGuard.marketplace` and `extensions.gallery.serviceUrl` pointing to 127.0.0.1:45822
    // - product.json has `extensionsGallery.serviceUrl` patched to 127.0.0.1:45822 with `_devGuardOriginalServiceUrl`
    files.set(settingsPath, JSON.stringify({
        'editor.fontSize': 14,
        'extensions.gallery.serviceUrl': 'http://127.0.0.1:45822/_apis/public/gallery',
        'devGuard.marketplace': 'http://127.0.0.1:45822/_apis/public/gallery'
    }, null, 4));
    files.set(productPath, JSON.stringify({
        extensionsGallery: {
            serviceUrl: 'http://127.0.0.1:45822/_apis/public/gallery',
            extensionUrlTemplate: 'http://127.0.0.1:45822/_apis/public/gallery/vscode/{publisher}/{name}/latest',
            _devGuardOriginalServiceUrl: 'https://marketplace.visualstudio.com/_apis/public/gallery',
            _devGuardOriginalExtensionUrlTemplate: 'https://www.vscode-unpkg.net/_gallery/{publisher}/{name}/latest'
        }
    }));
    files.set(path.join(extensionsDir, 'extensions.json'), JSON.stringify([
        { identifier: { id: 'yeeth.dev-guard' } }
    ]));

    const fakeContext = {
        extensionPath: extPath,
        extension: { id: 'yeeth.dev-guard' },
        globalStorageUri: { fsPath: storageDir }
    };
    const fakeVscode = { env: { appRoot } };

    // 1. Write the uninstall restore manifest (user originally had custom Open VSX URL in devGuard.marketplace and default gallery).
    writeUninstallRestoreManifest(fakeContext, fakeVscode, {
        savedGalleryServiceUrl: '',
        savedDevGuardMarketplace: 'https://open-vsx.org/vscode/gallery',
        upstreamServiceUrl: 'https://marketplace.visualstudio.com/_apis/public/gallery'
    }, fakeIo);

    // 2. Self-uninstall detector starts false while installed, and becomes true when marked in `.obsolete` or removed from `extensions.json`.
    const isUninstalled = createSelfUninstallDetector(fakeContext, fakeIo);
    assert.equal(isUninstalled(), false);

    files.set(path.join(extensionsDir, '.obsolete'), JSON.stringify({ 'yeeth.dev-guard-0.1.3': true }));
    assert.equal(isUninstalled(), true);

    // 3. Running `runUninstallRestore` (as `scripts/uninstall.js` and `checkSelfUninstall` do) reverts both `settings.json` and `product.json`.
    const restored = runUninstallRestore({
        context: fakeContext,
        restoreProductJsonGallery,
        userDirs: [userDir],
        io: fakeIo
    });
    assert.equal(restored, true);

    const updatedSettings = JSON.parse(files.get(settingsPath));
    assert.equal(updatedSettings['editor.fontSize'], 14, 'unrelated user settings are untouched');
    assert.equal(updatedSettings['extensions.gallery.serviceUrl'], undefined, 'empty prior galleryServiceUrl deletes loopback override');
    assert.equal(updatedSettings['devGuard.marketplace'], 'https://open-vsx.org/vscode/gallery', 'prior custom marketplace URL is restored');

    const updatedProduct = JSON.parse(files.get(productPath));
    assert.equal(updatedProduct.extensionsGallery.serviceUrl, 'https://marketplace.visualstudio.com/_apis/public/gallery');
    assert.equal(updatedProduct.extensionsGallery.extensionUrlTemplate, 'https://www.vscode-unpkg.net/_gallery/{publisher}/{name}/latest');
    assert.equal(updatedProduct.extensionsGallery._devGuardOriginalServiceUrl, undefined);

    // 4. Verify `restoreMarketplaceSettingsFile` is a no-op when settings do not point to a loopback URL,
    //    and a second `runUninstallRestore` call (e.g. during IDE shutdown/update) is an immediate no-op
    //    because `uninstall-restore.json` was marked `restored: true`.
    assert.equal(restoreMarketplaceSettingsFile(settingsPath, {}, fakeIo), false);
    assert.equal(runUninstallRestore({
        context: fakeContext,
        restoreProductJsonGallery: () => { throw new Error('must not touch appRoot after restored: true'); },
        userDirs: [userDir],
        io: fakeIo
    }), false);

    // 5. When `usedProductJson: false` (e.g. Cursor), `appRoot` is never touched during uninstall restore.
    writeUninstallRestoreManifest(fakeContext, fakeVscode, {
        usedProductJson: false,
        savedGalleryServiceUrl: '',
        savedDevGuardMarketplace: ''
    }, fakeIo);
    let touchedProductJson = false;
    runUninstallRestore({
        context: fakeContext,
        restoreProductJsonGallery: () => { touchedProductJson = true; return true; },
        userDirs: [userDir],
        io: fakeIo
    });
    assert.equal(touchedProductJson, false, 'Cursor uninstall must never touch appRoot product.json');
});

test('proxy server unrefs listening socket and closes keep-alive connections immediately on shutdown', async () => {
    const { spawn } = require('node:child_process');
    const proxy = createMarketplaceProxy({
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => []
    });
    const port = await proxy.start(0);

    // 1. Open a persistent keep-alive connection and a long-lived `/_devguard/events` stream,
    //    then verify `proxy.stop()` resolves in <100ms instead of hanging for keep-alive timeout.
    const agent = new http.Agent({ keepAlive: true });
    await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/_apis/public/gallery`, { agent }, res => {
            res.resume();
            res.on('end', resolve);
        }).on('error', reject);
    });
    const streamReq = http.get(`http://127.0.0.1:${port}/_devguard/events`);
    streamReq.on('error', () => {});

    const startedStop = Date.now();
    await proxy.stop();
    const stopElapsed = Date.now() - startedStop;
    agent.destroy();
    streamReq.destroy();
    assert.ok(stopElapsed < 500, `Expected proxy.stop() to close keep-alive sockets immediately, took ${stopElapsed}ms`);

    // 2. Verify a Node child process that starts the proxy without calling `stop()`
    //    still exits on its own in <1s because `srv.unref()` does not hold the event loop open.
    const exitCode = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [
            '-e',
            'const { createMarketplaceProxy } = require("./proxy/server"); const p = createMarketplaceProxy({ getUpstream: () => ({ serviceUrl: "", registry: null }), getAdvisories: () => [] }); p.start(0);'
        ], { cwd: require('node:path').resolve(__dirname, '..'), stdio: 'ignore' });
        const timer = setTimeout(() => { child.kill(); reject(new Error('Child process hung due to refd server handle')); }, 2000);
        child.on('exit', code => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(exitCode, 0);
});

test('peer verification never leaks the secret and rejects squatters that relay the challenge to a real proxy', async () => {
    // 1. A "smart" squatter: it reads any `x-devguard-token` we send and uses it
    //    to answer the challenge. This passed before the fix, because the secret
    //    was sent along with the challenge.
    let stolenToken;
    const smartSquatter = await startMockServer((req, res) => {
        stolenToken = req.headers['x-devguard-token'];
        const nonce = new URL(req.url, 'http://x').searchParams.get('nonce') || '';
        const port = req.socket.localPort;
        const mac = stolenToken ? computeHandshakeMac(stolenToken, nonce, port) : 'no-secret';
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ mac }));
    });
    const smartPort = Number(new URL(smartSquatter.url).port);

    // 2. A "relay" squatter: it forwards our challenge to a REAL Dev-Guard proxy
    //    (same secret, different port) and returns that proxy's valid answer.
    const realProxy = createMarketplaceProxy({ secret: TEST_SECRET, getUpstream: () => ({ serviceUrl: '' }), getAdvisories: () => [] });
    const realPort = await realProxy.start(0);
    const relaySquatter = await startMockServer(async (req, res) => {
        const relayed = await fetch(`http://127.0.0.1:${realPort}${req.url}`).then(r => r.text()).catch(() => '{}');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(relayed);
    });
    const relayPort = Number(new URL(relaySquatter.url).port);

    const victim1 = createMarketplaceProxy({ secret: TEST_SECRET, getUpstream: () => ({ serviceUrl: '' }), getAdvisories: () => [] });
    const victim2 = createMarketplaceProxy({ secret: TEST_SECRET, getUpstream: () => ({ serviceUrl: '' }), getAdvisories: () => [] });
    try {
        const bound1 = await victim1.start(smartPort);
        assert.equal(stolenToken, undefined, 'the challenge request must never carry the secret');
        assert.notEqual(bound1, smartPort, 'must not trust a squatter that cannot prove the secret');

        const bound2 = await victim2.start(relayPort);
        assert.notEqual(bound2, relayPort, 'a relayed answer is bound to the real proxy port, so it must fail');
    } finally {
        await victim1.stop();
        await victim2.stop();
        await realProxy.stop();
        await smartSquatter.close();
        await relaySquatter.close();
    }
});

test('HTTP peer decisions require the one-time decisionToken and work from Node fetch', async () => {
    const mockPkgscan = await startMockServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'unscanned' }));
    });
    const mockUpstream = await startMockServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        res.end('UNSCANNED-VSIX');
    });
    // `defer` = this window doesn't decide; it waits for a peer window to POST the decision.
    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        onUnscannedInstall: async () => 'defer',
        pkgscanBaseUrl: mockPkgscan.url
    });
    const port = await proxy.start(0);

    // Listen on the peer event stream (like a second window would) to learn the decisionToken.
    let unscannedEvent = null;
    const streamReq = http.get({
        hostname: '127.0.0.1', port, path: '/_devguard/events', headers: { 'x-devguard-token': TEST_SECRET }
    }, res => {
        res.setEncoding('utf8');
        res.on('data', chunk => {
            for (const line of chunk.split('\n')) {
                if (!line.trim()) continue;
                const msg = JSON.parse(line);
                if (msg.event === 'unscanned') unscannedEvent = msg;
            }
        });
    });
    streamReq.on('error', () => {});

    const postDecision = body => fetch(`http://127.0.0.1:${port}/_devguard/decision`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-devguard-token': TEST_SECRET },
        body: JSON.stringify(body)
    });
    const sleep = ms => new Promise(r => setTimeout(r, ms));

    try {
        await sleep(30);
        const assetPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/acme/peer-ext/1.0.0`, 'acme', 'peer-ext', '1.0.0');
        let settled = false;
        const vsixPromise = fetch(`http://127.0.0.1:${port}/asset/${assetPath}/${ASSET_VSIX}`)
            .then(r => { settled = true; return r; });

        for (let i = 0; i < 50 && !unscannedEvent; i++) await sleep(10);
        assert.ok(unscannedEvent && unscannedEvent.decisionToken, 'peer stream receives the unscanned prompt with a token');
        const key = unscannedEvent.key;

        // Missing or wrong token: request is accepted but the decision is ignored.
        assert.equal((await postDecision({ key, decision: 'continue' })).status, 200);
        assert.equal((await postDecision({ key, decision: 'continue', decisionToken: 'f'.repeat(32) })).status, 200);
        await sleep(30);
        assert.equal(settled, false, 'decision without the right token must not approve the install');

        // Correct token, sent with Node fetch (which adds `sec-fetch-mode: cors`), resolves the prompt.
        await postDecision({ key, decision: 'continue', decisionToken: unscannedEvent.decisionToken });
        const vsixRes = await vsixPromise;
        assert.equal(vsixRes.status, 200);
        assert.equal(await vsixRes.text(), 'UNSCANNED-VSIX');
    } finally {
        streamReq.destroy();
        await proxy.stop();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});

test('asset URLs must be signed, loopback asset hosts are refused by default, and publisher/name must match whole path segments', () => {
    const base = 'https://open-vsx.org/vscode/asset/good/clean-ext/1.0.0';
    const signed = signAssetBase(TEST_SECRET, { decodedBase: base, publisher: 'good', name: 'clean-ext', version: '1.0.0', platform: 'universal' });
    const opts = { secret: TEST_SECRET, publisher: 'good', name: 'clean-ext', version: '1.0.0', platform: 'universal', proxyOrigin: 'http://127.0.0.1:1' };

    assert.equal(decodeAndVerifyAssetBase(signed, opts), base, 'valid signature is accepted');
    const unsigned = Buffer.from(base, 'utf8').toString('base64url');
    assert.equal(decodeAndVerifyAssetBase(unsigned, opts), null, 'unsigned (legacy) asset base is rejected');
    assert.equal(decodeAndVerifyAssetBase(signed, { ...opts, version: '2.0.0' }), null, 'signature is bound to the version');

    assert.equal(isAllowedAssetBaseUrl('http://127.0.0.1:6379/x/good/clean-ext', { publisher: 'good', name: 'clean-ext' }), false, 'loopback refused by default');
    assert.equal(isAllowedAssetBaseUrl('http://127.0.0.1:6379/x/good/clean-ext', { publisher: 'good', name: 'clean-ext', allowLoopback: true }), true);
    assert.equal(isAllowedAssetBaseUrl('https://open-vsx.org/vscode/asset/good/clean-ext-evil/1.0.0', { publisher: 'good', name: 'clean-ext' }), false, 'partial name must not match');
    assert.equal(isAllowedAssetBaseUrl('https://open-vsx.org/vscode/asset/good/clean-ext/1.0.0', { publisher: 'good', name: 'clean-ext' }), true);
});

test('security hardening blocks port squatters, browser CSRF/DNS rebinding, and SSRF', async () => {
    const rogueSquatter = await startMockServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ fake: true }));
    });
    const squatterPort = Number(new URL(rogueSquatter.url).port);

    const mockUpstream = await startMockServer((req, res) => {
        if (req.url.endsWith(`/${ASSET_VSIX}`)) {
            res.writeHead(200, { 'content-type': 'application/octet-stream' });
            res.end('CLEAN-VSIX-BINARY-BYTES');
            return;
        }
        res.writeHead(200, { 'content-type': 'text/markdown' });
        res.end('# Clean README');
    });

    const mockPkgscan = await startMockServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
            status: 'completed',
            flaggedCount: 0,
            engines: [{ id: 'guarddog', status: 'done', verdict: 'pass', findingCount: 0 }]
        }));
    });

    const blocked = [];
    const proxy = createMarketplaceProxy({
        secret: TEST_SECRET,
        allowLoopbackAssets: true,
        getUpstream: () => ({ serviceUrl: 'https://marketplace.cursorapi.com/_apis/public/gallery', registry: 'cursor-marketplace' }),
        getAdvisories: () => [],
        onBlockedDownload: info => blocked.push(info),
        pkgscanBaseUrl: mockPkgscan.url
    });

    try {
        // 1. Port-squatting protection: `squatterPort` is occupied by a non-DevGuard server,
        //    so `proxy.start(squatterPort)` refuses to trust it and binds a fresh ephemeral port.
        const boundPort = await proxy.start(squatterPort);
        assert.notEqual(boundPort, squatterPort, 'must not trust an unverified squatter on preferredPort');

        // 2. Browser Origin & Host (DNS rebinding) protection:
        const badOriginRes = await fetch(`http://127.0.0.1:${boundPort}/_apis/public/gallery`, {
            headers: { Origin: 'https://evil.example.com' }
        });
        assert.equal(badOriginRes.status, 403);

        // 2b. Browser "simple" loads (like `<img src>`) carry no Origin but do send
        //     `sec-fetch-site: cross-site`. They must not reach `/asset/` and trigger IDE prompts.
        const imgLikePath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/good/clean-ext/1.0.0`, 'good', 'clean-ext', '1.0.0');
        const crossSiteRes = await fetch(`http://127.0.0.1:${boundPort}/asset/${imgLikePath}/${ASSET_VSIX}`, {
            headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'image' }
        });
        assert.equal(crossSiteRes.status, 403, 'cross-site browser request without Origin must be rejected');
        assert.equal(blocked.length, 0);

        // 3. Internal control endpoints (`/_devguard/*`) reject unauthenticated local calls:
        const unauthEvents = await fetch(`http://127.0.0.1:${boundPort}/_devguard/events`);
        assert.equal(unauthEvents.status, 403);
        const unauthDecision = await fetch(`http://127.0.0.1:${boundPort}/_devguard/decision`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ key: 'acme.unscanned@1.0.0', decision: 'continue' })
        });
        assert.equal(unauthDecision.status, 403);

        // 4. SSRF & Publisher/Asset mismatch protection on `/asset/`:
        //    Unsigned URLs are rejected outright, even when they point at an allowed host.
        const unsignedEnc = Buffer.from(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/good/clean-ext/1.0.0`, 'utf8').toString('base64url');
        const unsignedRes = await fetch(`http://127.0.0.1:${boundPort}/asset/${unsignedEnc}/good/clean-ext/1.0.0/universal/${ASSET_README}`);
        assert.equal(unsignedRes.status, 403, 'unsigned asset base must be rejected');

        //    Even a correctly signed URL is rejected when its host is not a trusted gallery CDN.
        const ssrfPath = signedAssetPath('https://evil.example.com/extensions/good/ext/1.0.0', 'good', 'ext', '1.0.0');
        const ssrfRes = await fetch(`http://127.0.0.1:${boundPort}/asset/${ssrfPath}/${ASSET_README}`);
        assert.equal(ssrfRes.status, 403, 'untrusted asset host must be rejected');

        const mismatchPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/evil/other-ext/1.0.0`, 'good', 'clean-ext', '1.0.0');
        const mismatchRes = await fetch(`http://127.0.0.1:${boundPort}/asset/${mismatchPath}/${ASSET_README}`);
        assert.equal(mismatchRes.status, 403, 'mismatched publisher/name in asset base URL must be rejected');

        // 5. A correctly signed URL for a clean, scanned extension passes through unchanged:
        const validPath = signedAssetPath(`${mockUpstream.url}/open-vsx-mirror/vscode/asset/good/clean-ext/1.0.0`, 'good', 'clean-ext', '1.0.0');
        const vsixRes = await fetch(`http://127.0.0.1:${boundPort}/asset/${validPath}/${ASSET_VSIX}`);
        assert.equal(vsixRes.status, 200);
        assert.equal(await vsixRes.text(), 'CLEAN-VSIX-BINARY-BYTES');
        assert.equal(blocked.length, 0);
    } finally {
        await proxy.stop();
        await rogueSquatter.close();
        await mockUpstream.close();
        await mockPkgscan.close();
    }
});









