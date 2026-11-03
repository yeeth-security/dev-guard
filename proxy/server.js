/**
 * Lightweight local HTTP marketplace proxy for Dev-Guard.
 *
 * Why this file exists:
 *   Intercepts extension gallery traffic on `127.0.0.1` so Dev-Guard can:
 *     1. Inject pkgscan.dev security scan results and advisory warnings into
 *        the top of every extension's README (`Content.Details`).
 *     2. Block VSIX package downloads (`VSIXPackage` and `Code.Manifest` during
 *        install) when an extension version matches a security advisory or a
 *        blocking pkgscan.dev engine verdict, and prompt the user when an
 *        extension version has not been scanned on pkgscan.dev yet.
 */

const crypto = require('crypto');
const http = require('http');
const { DEFAULT_PROXY_PORT, PROXY_GALLERY_PATH } = require('./config');
const { buildPkgscanUrls, createScanFetcher, scanBlockAdvisory, injectReadmeScanData, DEFAULT_PKGSCAN_BASE_URL } = require('./readme');
const {
    MAX_BODY_BYTES,
    loadOrCreateProxySecret,
    safeEqual,
    computeHandshakeMac,
    verifyPeerServer,
    isAllowedHost,
    isAllowedOrigin,
    isBrowserRequest,
    isInternalPeerAuthorized,
    signAssetBase,
    decodeAndVerifyAssetBase
} = require('./security');
const { isPlatformMatch, normalizeRegistrySlug } = require('../advisories/registry');
const { severityRank } = require('../notifier');

const ASSET_README = 'Microsoft.VisualStudio.Services.Content.Details';
const ASSET_MANIFEST = 'Microsoft.VisualStudio.Code.Manifest';
const ASSET_ICON = 'Microsoft.VisualStudio.Services.Icons.Default';
const ASSET_VSIX = 'Microsoft.VisualStudio.Services.VSIXPackage';
const ASSET_SIG = 'Microsoft.VisualStudio.Services.VsixSignature';
const RECENT_BLOCK_TTL_MS = 5000;
const UNSCANNED_APPROVAL_TTL_MS = 5 * 60 * 1000;
const DECISION_TIMEOUT_MS = 50 * 1000;
const CURSOR_MIRROR_PREFIX = 'https://marketplace.cursorapi.com/open-vsx-mirror/';
const OPENVSX_PREFIX = 'https://open-vsx.org/';
const CURSOR_GALLERY_PREFIX = 'https://marketplace.cursorapi.com/_apis/public/gallery';
const OPENVSX_GALLERY_PREFIX = 'https://open-vsx.org/vscode/gallery';
const MS_LATEST_PREFIX = 'https://marketplace.visualstudio.com/_apis/public/gallery/vscode/';
const UNPKG_LATEST_PREFIX = 'https://www.vscode-unpkg.net/_gallery/';

function openVsxFallbackUrl(url) {
    const str = String(url || '');
    if (str.startsWith(CURSOR_MIRROR_PREFIX)) return `${OPENVSX_PREFIX}${str.slice(CURSOR_MIRROR_PREFIX.length)}`;
    if (str.startsWith(CURSOR_GALLERY_PREFIX)) return `${OPENVSX_GALLERY_PREFIX}${str.slice(CURSOR_GALLERY_PREFIX.length)}`;
    if (str.startsWith(MS_LATEST_PREFIX)) return `${UNPKG_LATEST_PREFIX}${str.slice(MS_LATEST_PREFIX.length)}`;
    return null;
}

const QUERY_CAPABILITIES = {
    filtering: [
        { name: 'Tag', value: 1 }, { name: 'ExtensionId', value: 4 }, { name: 'Category', value: 5 },
        { name: 'ExtensionName', value: 7 }, { name: 'Target', value: 8 }, { name: 'Featured', value: 9 },
        { name: 'SearchText', value: 10 }, { name: 'ExcludeWithFlags', value: 12 }
    ],
    sorting: [
        { name: 'NoneOrRelevance', value: 0 }, { name: 'LastUpdatedDate', value: 1 }, { name: 'Title', value: 2 },
        { name: 'PublisherName', value: 3 }, { name: 'InstallCount', value: 4 }, { name: 'AverageRating', value: 6 },
        { name: 'PublishedDate', value: 10 }, { name: 'WeightedRating', value: 12 }
    ],
    flags: [
        { name: 'None', value: 0 }, { name: 'IncludeVersions', value: 1 }, { name: 'IncludeFiles', value: 2 },
        { name: 'IncludeCategoryAndTags', value: 4 }, { name: 'IncludeSharedAccounts', value: 8 },
        { name: 'IncludeVersionProperties', value: 16 }, { name: 'ExcludeNonValidated', value: 32 },
        { name: 'IncludeInstallationTargets', value: 64 }, { name: 'IncludeAssetUri', value: 128 },
        { name: 'IncludeStatistics', value: 256 }, { name: 'IncludeLatestVersionOnly', value: 512 },
        { name: 'Unpublished', value: 4096 }, { name: 'IncludeNameConflictInfo', value: 32768 },
        { name: 'IncludeLatestPrereleaseAndStableVersionOnly', value: 65536 }
    ]
};

function buildGalleryManifest(proxyOrigin) {
    const base = `${proxyOrigin}${PROXY_GALLERY_PATH}`;
    return {
        version: '3.0-preview.1',
        resources: [
            { id: `${base}/extensionquery`, type: 'ExtensionQueryService' },
            { id: `${base}/vscode/{publisher}/{name}/latest`, type: 'ExtensionLatestVersionUriTemplate' }
        ],
        capabilities: { extensionQuery: QUERY_CAPABILITIES, signing: { allRepositorySigned: false, allPublicRepositorySigned: false } }
    };
}

function buildEmptyQueryResult() {
    return {
        results: [{
            extensions: [],
            resultMetadata: [{ metadataType: 'ResultCount', metadataItems: [{ name: 'TotalCount', count: 0 }] }]
        }]
    };
}

function matchAdvisoryForExtension({ publisher, name, version, platform, registry, assetBaseUrl, advisories = [] }) {
    const extId = `${publisher || ''}.${name || ''}`.toLowerCase();
    const normReg = normalizeRegistrySlug(registry);
    const base = String(assetBaseUrl || '').toLowerCase();
    const isOpenVsxBacked = normReg === 'openvsx' || normReg === 'cursor-marketplace'
        || base.includes('open-vsx.org') || base.includes('/open-vsx-mirror');

    const matches = (Array.isArray(advisories) ? advisories : []).filter(entry => {
        if (!entry || !entry.extensionId || entry.extensionId.toLowerCase() !== extId) return false;
        const verOk = entry.version === '*' || !version || version === 'latest' || entry.version === version;
        if (!verOk || !isPlatformMatch(entry.platform, platform)) return false;
        const advReg = normalizeRegistrySlug(entry.registry);
        if (!advReg || advReg === '*' || !normReg) return true;
        if (isOpenVsxBacked && (advReg === 'openvsx' || advReg === 'cursor-marketplace')) return true;
        return advReg === normReg;
    });
    if (matches.length === 0) return null;
    matches.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    return matches[0];
}

function rewriteGalleryExtension(ext, { proxyOrigin, getAdvisories, isAllowlisted, registry, uuidByExtId, secret }) {
    if (!ext || typeof ext !== 'object' || !Array.isArray(ext.versions)) return ext;
    const publisher = (ext.publisher && ext.publisher.publisherName) || '';
    const name = ext.extensionName || '';
    if (!publisher || !name) return ext;

    const extId = `${publisher}.${name}`.toLowerCase();
    if (uuidByExtId && typeof ext.extensionId === 'string' && ext.extensionId) {
        uuidByExtId.set(extId, ext.extensionId.toLowerCase());
    }
    const allowlisted = typeof isAllowlisted === 'function' ? Boolean(isAllowlisted(extId)) : false;
    const advisories = typeof getAdvisories === 'function' ? getAdvisories() : [];

    for (const ver of ext.versions) {
        if (!ver || typeof ver !== 'object') continue;
        const origAsset = ver.assetUri || ver.fallbackAssetUri;
        const origFallback = ver.fallbackAssetUri || ver.assetUri;
        if (!origAsset) continue;

        const version = ver.version || 'latest';
        const platform = ver.targetPlatform || 'universal';
        const advisory = matchAdvisoryForExtension({ publisher, name, version, platform, registry, assetBaseUrl: origAsset, advisories });
        const shouldBlock = Boolean(advisory && !allowlisted);

        const encAsset = secret
            ? signAssetBase(secret, { decodedBase: origAsset, publisher, name, version, platform })
            : Buffer.from(String(origAsset).replace(/\/+$/, ''), 'utf8').toString('base64url');
        const suffix = `${encodeURIComponent(publisher)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/${encodeURIComponent(platform)}`;
        ver.assetUri = `${proxyOrigin}/asset/${encAsset}/${suffix}`;

        const cleanFallback = openVsxFallbackUrl(origFallback) || origFallback;
        const hasIcon = Array.isArray(ver.files) && ver.files.some(f => f && f.assetType === ASSET_ICON);
        if (shouldBlock && origFallback && !hasIcon) {
            const encFallback = secret
                ? signAssetBase(secret, { decodedBase: origFallback, publisher, name, version, platform })
                : Buffer.from(String(origFallback).replace(/\/+$/, ''), 'utf8').toString('base64url');
            ver.fallbackAssetUri = `${proxyOrigin}/asset/${encFallback}/${suffix}`;
        } else if (origFallback) {
            ver.fallbackAssetUri = cleanFallback;
        }
        if (Array.isArray(ver.files)) {
            for (const f of ver.files) {
                if (!f || !f.assetType) continue;
                if (f.assetType === ASSET_README || f.assetType === ASSET_MANIFEST || f.assetType === ASSET_VSIX || f.assetType === ASSET_SIG) {
                    f.source = `${ver.assetUri}/${f.assetType}`;
                } else if (typeof f.source === 'string') {
                    f.source = openVsxFallbackUrl(f.source) || f.source;
                }
            }
        }
    }
    return ext;
}

function readBody(req, maxBytes = MAX_BODY_BYTES) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        req.on('data', c => {
            total += c.length;
            if (total > maxBytes) {
                const err = new Error('Payload Too Large');
                err.statusCode = 413;
                reject(err);
                try { req.destroy(); } catch (_e) { /* ignore */ }
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

function corsHeaders(req, extra = {}) {
    const reqHeaders = req && req.headers && req.headers['access-control-request-headers'];
    const origin = (req && req.headers && req.headers.origin && isAllowedOrigin(req))
        ? req.headers.origin
        : 'vscode-file://vscode-app';
    return {
        'access-control-allow-origin': origin,
        'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD',
        'access-control-allow-headers': reqHeaders || 'Content-Type, Accept, Authorization, X-Market-Client-Id, X-Market-User-Id, VSCode-SessionId, X-Market-Search-Activity-Id, X-OG-Device-Group',
        'access-control-allow-private-network': 'true',
        'access-control-expose-headers': '*',
        'access-control-max-age': '86400',
        ...extra
    };
}

/**
 * Options worth knowing:
 *   - `allowLoopbackAssets`: TEST ONLY. Lets `/asset/` fetch from local mock servers.
 *   - `onPortChanged(port)`: called when the proxy moves to a new port because
 *     an unverified process took over the shared port. The caller must point
 *     the marketplace settings at the new port.
 */
function createMarketplaceProxy({ context, secret, getUpstream, getAdvisories, isAllowlisted, onBlockedDownload, onUnscannedInstall, onUnscannedDecision, onFlaggedReadmeViewed, onPortChanged, allowLoopbackAssets = false, pkgscanBaseUrl = DEFAULT_PKGSCAN_BASE_URL, fetchImpl = fetch }) {
    let server = null;
    let listeningPort = null;
    let standbyTimer = null;
    let peerStreamReq = null;
    let reconnecting = false;
    let lastBlockedUntil = 0;
    const proxySecret = secret || loadOrCreateProxySecret(context);
    const eventClients = new Set();
    const activeSockets = new Set();
    const blockedReasons = new Map();
    const uuidByExtId = new Map();
    const unscannedApproved = new Map();
    const pendingDecisions = new Map();
    const scanFetcher = createScanFetcher({ baseUrl: pkgscanBaseUrl, fetchImpl });

    function broadcastPeerEvent(payload) {
        const line = `${JSON.stringify(payload)}\n`;
        for (const client of eventClients) {
            try { client.write(line); } catch (_e) { eventClients.delete(client); }
        }
    }

    function emitBlockedDownload(payload) {
        try { onBlockedDownload?.(payload); } catch (_e) { /* ignore */ }
        broadcastPeerEvent({ event: 'blocked', ...payload });
    }

    function isUnscannedApproved(extVerKey) {
        const exp = unscannedApproved.get(extVerKey);
        if (!exp) return false;
        if (Date.now() > exp) { unscannedApproved.delete(extVerKey); return false; }
        return true;
    }

    function resolveUnscannedDecision(key, decision, decisionToken) {
        const entry = pendingDecisions.get(key);
        if (!entry) return false;
        if (decisionToken !== undefined && !safeEqual(String(decisionToken), entry.decisionToken)) {
            return false;
        }
        if (decision === 'continue') {
            unscannedApproved.set(key, Date.now() + UNSCANNED_APPROVAL_TTL_MS);
        }
        clearTimeout(entry.timer);
        pendingDecisions.delete(key);
        if (entry.payload) {
            try { onUnscannedDecision?.({ ...entry.payload, decision }); } catch (_e) { /* ignore */ }
            broadcastPeerEvent({ event: 'unscanned_decision', ...entry.payload, decision });
        }
        entry.resolve(decision);
        return true;
    }

    function promptUnscannedDecision(payload) {
        if (isUnscannedApproved(payload.key)) return Promise.resolve('continue');
        if (pendingDecisions.has(payload.key)) return pendingDecisions.get(payload.key).promise;
        if (typeof onUnscannedInstall !== 'function' && eventClients.size === 0) return Promise.resolve('continue');

        let resolveFn;
        const promise = new Promise(resolve => { resolveFn = resolve; });
        const decisionToken = crypto.randomBytes(16).toString('hex');
        const timer = setTimeout(() => resolveUnscannedDecision(payload.key, 'cancel'), DECISION_TIMEOUT_MS);
        if (typeof timer.unref === 'function') timer.unref();
        pendingDecisions.set(payload.key, { promise, resolve: resolveFn, timer, payload, decisionToken });

        broadcastPeerEvent({ event: 'unscanned', decisionToken, ...payload });
        if (typeof onUnscannedInstall === 'function') {
            Promise.resolve(onUnscannedInstall({ ...payload, hasPeers: eventClients.size > 0 }))
                .then(decision => { if (decision && decision !== 'defer') resolveUnscannedDecision(payload.key, decision); })
                .catch(() => resolveUnscannedDecision(payload.key, 'cancel'));
        }
        return promise;
    }

    function sendBlockedInstallResponse(req, res, { assetType, extId, publisher, name, version, reason }) {
        const until = Date.now() + RECENT_BLOCK_TTL_MS;
        lastBlockedUntil = until;
        blockedReasons.set(extId, until);
        const uuid = uuidByExtId.get(extId);
        if (uuid) blockedReasons.set(uuid, until);
        if (assetType === ASSET_MANIFEST) {
            res.writeHead(200, corsHeaders(req, { 'content-type': 'application/json' }));
            res.end(JSON.stringify({
                name, publisher,
                version: '0.0.0-blocked-by-dev-guard',
                engines: { vscode: '^999.0.0' }
            }));
            return;
        }
        res.writeHead(403, corsHeaders(req, { 'content-type': 'application/json' }));
        res.end(JSON.stringify({ error: 'blocked_by_dev_guard', message: `Can't install '${publisher}.${name}@${version}': ${reason}.` }));
    }

    async function fetchWithMirrorFallback(url, options) {
        const primary = await fetchImpl(url, options).catch(() => null);
        if (primary && primary.ok) return primary;
        const altUrl = openVsxFallbackUrl(url);
        if (altUrl) {
            const fallbackRes = await fetchImpl(altUrl, options).catch(() => null);
            if (fallbackRes && fallbackRes.ok) return fallbackRes;
        }
        return primary;
    }

    async function handleAsset(req, res, pathname, search, proxyOrigin, upstream) {
        if (pathname.startsWith('/asset/blocked/')) {
            res.writeHead(200, corsHeaders(req, { 'content-type': 'application/json' }));
            res.end(JSON.stringify({ name: 'blocked', publisher: 'dev-guard', version: '1.0.0', engines: { vscode: '^999.0.0' } }));
            return;
        }
        const parts = pathname.slice('/asset/'.length).split('/');
        if (parts.length < 6) { res.writeHead(400); res.end('Invalid asset path'); return; }
        const [encBase, pubEnc, nameEnc, verEnc, platEnc, ...assetRest] = parts;
        const [publisher, name, version, platform] = [pubEnc, nameEnc, verEnc, platEnc].map(decodeURIComponent);
        const assetType = assetRest.join('/');
        const extId = `${publisher}.${name}`.toLowerCase();
        const extVerKey = `${extId}@${version || 'latest'}`;

        const decodedBase = decodeAndVerifyAssetBase(encBase, {
            secret: proxySecret,
            publisher,
            name,
            version,
            platform,
            upstreamServiceUrl: upstream.serviceUrl,
            proxyOrigin,
            allowLoopback: allowLoopbackAssets
        });
        if (!decodedBase) {
            res.writeHead(403, corsHeaders(req, { 'content-type': 'application/json' }));
            res.end(JSON.stringify({ error: 'invalid_or_untrusted_asset_base' }));
            return;
        }

        const advisories = typeof getAdvisories === 'function' ? getAdvisories() : [];
        const allowlisted = typeof isAllowlisted === 'function' ? Boolean(isAllowlisted(extId)) : false;
        let advisory = matchAdvisoryForExtension({
            publisher, name, version, platform, registry: upstream.registry, assetBaseUrl: decodedBase, advisories
        });
        let blockSource = advisory ? 'advisory' : null;

        const isInstallCheck = assetType === ASSET_VSIX || assetType === ASSET_SIG || (assetType === ASSET_MANIFEST && !req.headers.origin);
        let scan = null;
        if (!advisory && !allowlisted && isInstallCheck) {
            scan = await scanFetcher.getScanData({ publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase });
            advisory = scanBlockAdvisory(scan, { publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase, baseUrl: pkgscanBaseUrl });
            if (advisory) blockSource = 'engine_scan';
        }

        if (isInstallCheck && advisory && !allowlisted) {
            const reason = advisory.title ? String(advisory.title).replace(/[_-]+/g, ' ') : 'Security advisory';
            emitBlockedDownload({
                id: `${publisher}.${name}`,
                version,
                platform,
                registry: upstream.registry || 'unknown',
                blockSource: blockSource || 'advisory',
                advisory
            });
            sendBlockedInstallResponse(req, res, { assetType, extId, publisher, name, version, reason });
            return;
        }

        if (isInstallCheck && !advisory && !allowlisted && (!scan || scan.status !== 'completed')) {
            const urls = buildPkgscanUrls({ publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase, baseUrl: pkgscanBaseUrl });
            const decision = await promptUnscannedDecision({
                key: extVerKey,
                id: `${publisher}.${name}`,
                publisher,
                name,
                version,
                platform,
                registry: upstream.registry || 'unknown',
                scanStatus: (scan && scan.status) || 'unscanned',
                reportUrl: urls.reportUrl
            });
            if (decision !== 'continue') {
                sendBlockedInstallResponse(req, res, {
                    assetType, extId, publisher, name, version,
                    reason: 'Not yet scanned on pkgscan.dev'
                });
                return;
            }
        }

        const targetAssetUrl = `${decodedBase}/${assetType}${search || ''}`;
        if (assetType === ASSET_README) {
            const [upstreamRes, readmeScan] = await Promise.all([
                fetchWithMirrorFallback(targetAssetUrl),
                scanFetcher.getScanData({ publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase })
            ]);
            const effectiveAdv = advisory || scanBlockAdvisory(readmeScan, {
                publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase, baseUrl: pkgscanBaseUrl
            });
            if (effectiveAdv) {
                try {
                    onFlaggedReadmeViewed?.({
                        id: `${publisher}.${name}`,
                        version,
                        registry: upstream.registry || 'unknown',
                        blockSource: advisory ? 'advisory' : 'engine_scan',
                        severity: effectiveAdv.severity || 'high',
                        allowlisted
                    });
                } catch (_e) { /* ignore telemetry callback errors */ }
            }
            const originalReadme = upstreamRes && upstreamRes.ok ? await upstreamRes.text() : '';
            const injected = injectReadmeScanData(originalReadme, {
                publisher, name, version, registry: upstream.registry, assetBaseUrl: decodedBase,
                scan: readmeScan, advisory, allowlisted, baseUrl: pkgscanBaseUrl
            });
            res.writeHead(200, corsHeaders(req, { 'content-type': 'text/markdown; charset=utf-8' }));
            res.end(injected);
            return;
        }

        const assetRes = await fetchWithMirrorFallback(targetAssetUrl);
        if (!assetRes || !assetRes.ok) {
            if (assetType === ASSET_MANIFEST) {
                res.writeHead(200, corsHeaders(req, { 'content-type': 'application/json' }));
                res.end(JSON.stringify({ name, publisher, version, engines: { vscode: '*' } }));
                return;
            }
            if (!assetRes) {
                res.writeHead(502, corsHeaders(req, { 'content-type': 'application/json' }));
                res.end(JSON.stringify({ error: 'upstream_unreachable' }));
                return;
            }
        }
        const bodyBuf = Buffer.from(await assetRes.arrayBuffer());
        const ct = (assetRes.headers && assetRes.headers.get && assetRes.headers.get('content-type')) || 'application/octet-stream';
        res.writeHead(assetRes.status, corsHeaders(req, { 'content-type': ct }));
        res.end(bodyBuf);
    }

    async function handleRequest(req, res) {
        if (!isAllowedHost(req) || !isAllowedOrigin(req)) {
            res.writeHead(403, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'forbidden_origin_or_host' }));
            return;
        }
        if (req.method === 'OPTIONS') { res.writeHead(204, corsHeaders(req)); res.end(); return; }
        const proxyOrigin = `http://127.0.0.1:${listeningPort}`;
        const urlObj = new URL(req.url || '/', proxyOrigin);
        const upstream = typeof getUpstream === 'function' ? getUpstream() : { serviceUrl: '', registry: null };

        // Peer challenge. It is answered WITHOUT the secret header on purpose:
        // callers must never send the secret to a server they haven't verified.
        // The answer is a one-way hash tied to a random nonce and to the port
        // this socket is bound to, so it reveals nothing reusable.
        if (req.method === 'GET' && urlObj.pathname === '/_devguard/verify') {
            const nonce = urlObj.searchParams.get('nonce') || '';
            if (isBrowserRequest(req) || !/^[a-f0-9]{32}$/i.test(nonce)) {
                res.writeHead(403, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'unauthorized_peer' }));
                return;
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true, mac: computeHandshakeMac(proxySecret, nonce, req.socket.localPort) }));
            return;
        }
        if (urlObj.pathname.startsWith('/_devguard/')) {
            if (!isInternalPeerAuthorized(req, proxySecret)) {
                res.writeHead(403, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'unauthorized_peer' }));
                return;
            }
            if (req.method === 'GET' && urlObj.pathname === '/_devguard/events') {
                res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-cache', connection: 'keep-alive' });
                eventClients.add(res);
                req.on('close', () => eventClients.delete(res));
                return;
            }
            if (req.method === 'POST' && urlObj.pathname === '/_devguard/decision') {
                try {
                    const body = JSON.parse((await readBody(req)).toString('utf8'));
                    // HTTP callers MUST send the one-time `decisionToken` for this prompt.
                    // `resolveUnscannedDecision` skips the token check when it is
                    // `undefined` (for calls from inside this window), so a missing token
                    // over HTTP would otherwise bypass the check entirely.
                    if (body && body.key && body.decision && typeof body.decisionToken === 'string') {
                        resolveUnscannedDecision(body.key, body.decision, body.decisionToken);
                    }
                } catch (_e) { /* ignore */ }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ ok: true }));
                return;
            }
            res.writeHead(404); res.end();
            return;
        }
        if (req.method === 'GET' && (urlObj.pathname === '/' || urlObj.pathname === PROXY_GALLERY_PATH)) {
            res.writeHead(200, corsHeaders(req, { 'content-type': 'application/json' }));
            res.end(JSON.stringify(buildGalleryManifest(proxyOrigin)));
            return;
        }
        if (urlObj.pathname.startsWith('/asset/')) return handleAsset(req, res, urlObj.pathname, urlObj.search, proxyOrigin, upstream);

        const rel = urlObj.pathname.startsWith(PROXY_GALLERY_PATH) ? urlObj.pathname.slice(PROXY_GALLERY_PATH.length) : urlObj.pathname;
        let reqBody;
        if (req.method === 'POST' || req.method === 'PUT') {
            try {
                reqBody = await readBody(req);
            } catch (err) {
                res.writeHead((err && err.statusCode) || 413, corsHeaders(req, { 'content-type': 'application/json' }));
                res.end(JSON.stringify({ error: 'payload_too_large' }));
                return;
            }
        }

        if (req.method === 'POST' && rel === '/extensionquery' && reqBody) {
            try {
                const parsed = JSON.parse(reqBody.toString('utf8'));
                const flags = Number(parsed && parsed.flags) || 0;
                const criteria = (parsed && parsed.filters && parsed.filters[0] && parsed.filters[0].criteria) || [];
                // When VS Code/Cursor's `getDownloadUrl()` immediately queries `/extensionquery`
                // with `IncludeVersions` (`flags & 1`, without `IncludeLatestVersionOnly` `flags & 512`)
                // after a blocked install to build a "Try Downloading Manually..." button (often
                // querying by UUID `filterType: 4`), return an empty result so it never offers manual download.
                if ((flags & 1) !== 0) {
                    const now = Date.now();
                    const isVersionLookupAfterBlock = (flags & 512) === 0 && now < lastBlockedUntil;
                    const isBlockedFollowup = isVersionLookupAfterBlock || criteria.some(c => {
                        const val = String((c && c.value) || '').toLowerCase();
                        const exp = blockedReasons.get(val);
                        return Boolean(exp && now < exp);
                    });
                    if (isBlockedFollowup) {
                        res.writeHead(200, corsHeaders(req, { 'content-type': 'application/json; charset=utf-8' }));
                        res.end(JSON.stringify(buildEmptyQueryResult()));
                        return;
                    }
                }
            } catch (_e) { /* continue to upstream */ }
        }

        const targetUrl = `${String(upstream.serviceUrl || '').replace(/\/+$/, '')}${rel}${urlObj.search || ''}`;
        const headers = { accept: req.headers.accept || 'application/json;api-version=3.0-preview.1' };
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];

        const upstreamRes = await fetchWithMirrorFallback(targetUrl, { method: req.method, headers, body: reqBody });
        if (!upstreamRes) {
            res.writeHead(502, corsHeaders(req, { 'content-type': 'application/json' }));
            res.end(JSON.stringify({ error: 'upstream_unreachable' }));
            return;
        }
        const ct = (upstreamRes.headers && upstreamRes.headers.get && upstreamRes.headers.get('content-type')) || 'application/json';
        if (upstreamRes.ok && ct.includes('json')) {
            const data = await upstreamRes.json();
            const opts = { proxyOrigin, getAdvisories, isAllowlisted, registry: upstream.registry, uuidByExtId, secret: proxySecret };
            if (Array.isArray(data && data.results)) {
                data.results.forEach(r => Array.isArray(r && r.extensions) && r.extensions.forEach(ext => rewriteGalleryExtension(ext, opts)));
            } else if (data && Array.isArray(data.versions)) {
                rewriteGalleryExtension(data, opts);
            }
            res.writeHead(upstreamRes.status, corsHeaders(req, { 'content-type': 'application/json; charset=utf-8' }));
            res.end(JSON.stringify(data));
            return;
        }
        res.writeHead(upstreamRes.status, corsHeaders(req, { 'content-type': ct }));
        res.end(Buffer.from(await upstreamRes.arrayBuffer()));
    }

    function listenOnPort(port) {
        return new Promise((resolve, reject) => {
            const srv = http.createServer((req, res) => {
                handleRequest(req, res).catch(err => {
                    if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: 'proxy_error', message: String(err && err.message || err) }));
                });
            });
            // Unref both the listening server and every incoming socket so the
            // proxy never keeps the Extension Host process alive when Cursor or
            // VS Code closes or restarts to install an editor update.
            srv.on('connection', socket => {
                activeSockets.add(socket);
                if (typeof socket.unref === 'function') socket.unref();
                socket.on('close', () => activeSockets.delete(socket));
            });
            srv.once('error', reject);
            srv.listen({ port, host: '127.0.0.1', exclusive: true }, () => {
                if (typeof srv.unref === 'function') srv.unref();
                resolve({ srv, port: srv.address().port });
            });
        });
    }

    function clearStandby() {
        if (standbyTimer) { clearInterval(standbyTimer); standbyTimer = null; }
        if (peerStreamReq) { try { peerStreamReq.destroy(); } catch (_e) { /* ignore */ } peerStreamReq = null; }
    }

    function forceCloseServer() {
        clearStandby();
        listeningPort = null;
        for (const key of pendingDecisions.keys()) resolveUnscannedDecision(key, 'cancel');
        for (const client of eventClients) { try { client.destroy(); } catch (_e) { /* ignore */ } }
        eventClients.clear();
        for (const socket of activeSockets) { try { socket.destroy(); } catch (_e) { /* ignore */ } }
        activeSockets.clear();
        if (!server) return null;
        const srv = server;
        server = null;
        if (typeof srv.closeAllConnections === 'function') {
            try { srv.closeAllConnections(); } catch (_e) { /* ignore */ }
        }
        return srv;
    }

    // Immediately release the port if the parent Electron process disconnects or exits.
    const onProcessExit = () => {
        const srv = forceCloseServer();
        if (srv) { try { srv.close(); } catch (_e) { /* ignore */ } }
    };
    process.once('disconnect', onProcessExit);
    process.once('exit', onProcessExit);

    function postPeerDecision(port, key, decision, decisionToken) {
        fetchImpl(`http://127.0.0.1:${port}/_devguard/decision`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-devguard-token': proxySecret },
            body: JSON.stringify({ key, decision, decisionToken })
        }).catch(() => {});
    }

    function connectPeerEvents(port) {
        if (peerStreamReq || server || !listeningPort) return;
        const req = http.get({
            hostname: '127.0.0.1',
            port,
            path: '/_devguard/events',
            headers: { 'x-devguard-token': proxySecret }
        }, res => {
            if (res.statusCode !== 200) { res.resume(); return; }
            let buf = '';
            res.setEncoding('utf8');
            res.on('data', chunk => {
                buf += chunk;
                const lines = buf.split('\n');
                buf = lines.pop() || '';
                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const msg = JSON.parse(line);
                        if (msg.event === 'unscanned' && typeof onUnscannedInstall === 'function') {
                            Promise.resolve(onUnscannedInstall({ ...msg, fromPeer: true })).then(decision => {
                                if (decision && decision !== 'defer') postPeerDecision(port, msg.key, decision, msg.decisionToken);
                            }).catch(() => {});
                        } else if (msg.event === 'unscanned_decision') {
                            onUnscannedDecision?.({ ...msg, fromPeer: true });
                        } else {
                            onBlockedDownload?.({ ...msg, fromPeer: true });
                        }
                    } catch (_e) { /* ignore */ }
                }
            });
            res.on('close', () => { peerStreamReq = null; });
        });
        req.on('socket', s => { if (typeof s?.unref === 'function') s.unref(); });
        req.on('error', () => { peerStreamReq = null; });
        if (typeof req.socket?.unref === 'function') req.socket.unref();
        peerStreamReq = req;
    }

    /**
     * Re-verifies the listener on `port` before reconnecting to it.
     *
     * The old peer window may have closed, and a different process may now
     * hold the port. Reconnecting blindly would send our secret to it. If the
     * new listener fails the check, we stop trusting the port, move to a fresh
     * ephemeral port, and tell the caller so the settings follow us.
     */
    async function reconnectToVerifiedPeer(port) {
        if (reconnecting || peerStreamReq || server || !listeningPort) return;
        reconnecting = true;
        try {
            if (await verifyPeerServer(port, proxySecret)) {
                connectPeerEvents(port);
                return;
            }
            if (server || !listeningPort) return;
            const { srv, port: newPort } = await listenOnPort(0);
            clearStandby(); server = srv; listeningPort = newPort;
            try { onPortChanged?.(newPort); } catch (_e) { /* ignore */ }
        } catch (_e) {
            /* try again on the next standby tick */
        } finally {
            reconnecting = false;
        }
    }

    return {
        async start(preferredPort = DEFAULT_PROXY_PORT) {
            if (listeningPort) return listeningPort;
            try {
                const { srv, port } = await listenOnPort(preferredPort);
                clearStandby(); server = srv; listeningPort = port;
                return listeningPort;
            } catch (err) {
                if (err && err.code === 'EADDRINUSE' && preferredPort > 0) {
                    // Verify the listener on `preferredPort` is a genuine Dev-Guard peer
                    // holding our secret before trusting it. If verification fails, a rogue
                    // process is squatting the port — fall back to an ephemeral port (`0`).
                    const isVerifiedPeer = await verifyPeerServer(preferredPort, proxySecret);
                    if (!isVerifiedPeer) {
                        const { srv, port } = await listenOnPort(0);
                        clearStandby(); server = srv; listeningPort = port;
                        return listeningPort;
                    }
                    listeningPort = preferredPort;
                    connectPeerEvents(preferredPort);
                    if (!standbyTimer) {
                        standbyTimer = setInterval(() => {
                            if (server || !listeningPort) return;
                            listenOnPort(preferredPort)
                                .then(({ srv, port }) => { clearStandby(); server = srv; listeningPort = port; })
                                .catch(() => reconnectToVerifiedPeer(preferredPort));
                        }, 3000);
                        if (typeof standbyTimer.unref === 'function') standbyTimer.unref();
                    }
                    return listeningPort;
                }
                throw err;
            }
        },
        async stop() {
            process.removeListener('disconnect', onProcessExit);
            process.removeListener('exit', onProcessExit);
            const srv = forceCloseServer();
            if (!srv) return;
            await new Promise(resolve => srv.close(() => resolve()));
        },
        stopSync: onProcessExit,
        isRunning: () => Boolean(listeningPort),
        getPort: () => listeningPort
    };
}

module.exports = { ASSET_README, ASSET_MANIFEST, ASSET_ICON, ASSET_VSIX, ASSET_SIG, buildGalleryManifest, matchAdvisoryForExtension, rewriteGalleryExtension, createMarketplaceProxy };
