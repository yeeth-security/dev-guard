/**
 * Security primitives for hardening the local marketplace proxy against
 * port squatting, unauthorized local/browser requests, SSRF, and VSIX tampering.
 *
 * Why this file exists:
 *   The local proxy runs on `127.0.0.1`. Without authentication and origin/host
 *   checks, another local process or a malicious web page in the user's browser
 *   could squat the proxy port, pre-approve unscanned extensions, abuse `/asset/`
 *   as an open SSRF proxy, or serve a modified `.vsix` binary.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');

const SECRET_FILENAME = 'proxy-secret.key';
const SECRET_STATE_KEY = 'devGuard.proxySecret';
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB cap on incoming POST bodies
const DEFAULT_PROCESS_SECRET = crypto.randomBytes(32).toString('hex');

const TRUSTED_GALLERY_HOSTS = [
    'marketplace.visualstudio.com',
    '.vsassets.io',
    '.vscode-unpkg.net',
    'open-vsx.org',
    '.openvsx.org',
    'marketplace.cursorapi.com'
];

/**
 * Loads or generates a 256-bit per-user secret shared only across processes
 * that can read the user's `globalStorageUri` (`0o600` file permissions).
 */
function loadOrCreateProxySecret(context, io = fs) {
    const dir = context && context.globalStorageUri && context.globalStorageUri.fsPath;
    if (typeof dir === 'string' && dir) {
        const secretPath = path.join(dir, SECRET_FILENAME);
        try {
            if (io.existsSync(secretPath)) {
                const raw = String(io.readFileSync(secretPath, 'utf8')).trim();
                if (/^[a-f0-9]{64}$/i.test(raw)) return raw;
            }
            const generated = crypto.randomBytes(32).toString('hex');
            io.mkdirSync?.(dir, { recursive: true });
            io.writeFileSync(secretPath, `${generated}\n`, { encoding: 'utf8', mode: 0o600 });
            return generated;
        } catch (_e) { /* fall through to globalState / process secret */ }
    }
    try {
        const existing = context && context.globalState && context.globalState.get(SECRET_STATE_KEY);
        if (typeof existing === 'string' && /^[a-f0-9]{64}$/i.test(existing)) return existing;
        if (context && context.globalState && typeof context.globalState.update === 'function') {
            const generated = crypto.randomBytes(32).toString('hex');
            void context.globalState.update(SECRET_STATE_KEY, generated);
            return generated;
        }
    } catch (_e) { /* ignore */ }
    return DEFAULT_PROCESS_SECRET;
}

/** Constant-time string comparison for secrets and HMAC signatures. */
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
    } catch (_e) {
        return false;
    }
}

/** Computes the HMAC-SHA256 peer verification tag for a challenge nonce. */
function computeHandshakeMac(secret, nonce) {
    return crypto.createHmac('sha256', String(secret)).update(`devguard-peer:${nonce}`).digest('hex');
}

/**
 * Verifies that an existing listener on `port` is a genuine Dev-Guard proxy
 * holding the same `secret`. Prevents port-squatting replacement attacks.
 */
function verifyPeerServer(port, secret, timeoutMs = 1200) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const expectedMac = computeHandshakeMac(secret, nonce);
    return new Promise(resolve => {
        const req = http.get({
            hostname: '127.0.0.1',
            port,
            path: `/_devguard/verify?nonce=${nonce}`,
            headers: { 'x-devguard-token': secret },
            timeout: timeoutMs
        }, res => {
            if (res.statusCode !== 200) { res.resume(); resolve(false); return; }
            let body = '';
            res.setEncoding('utf8');
            res.on('data', c => { if (body.length < 1024) body += c; });
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(body);
                    resolve(Boolean(parsed && safeEqual(parsed.mac, expectedMac)));
                } catch (_e) { resolve(false); }
            });
        });
        req.on('timeout', () => { req.destroy(); resolve(false); });
        req.on('error', () => resolve(false));
    });
}

/** Rejects DNS-rebinding requests whose `Host` header is not localhost/loopback. */
function isAllowedHost(req) {
    const host = String((req && req.headers && req.headers.host) || '').trim().toLowerCase();
    if (!host) return true;
    return /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(host);
}

/** Rejects cross-origin requests from regular web browsers (`http:` / `https:` origins). */
function isAllowedOrigin(req) {
    const origin = req && req.headers && req.headers.origin;
    if (!origin) return true;
    const lower = String(origin).trim().toLowerCase();
    return lower.startsWith('vscode-file://') || lower.startsWith('vscode-webview://');
}

/** Ensures `/_devguard/*` control endpoints are only called by authenticated Node peers, never browsers. */
function isInternalPeerAuthorized(req, secret) {
    if (!req || !req.headers) return false;
    if (req.headers.origin || req.headers['sec-fetch-site'] || req.headers['sec-fetch-mode']) return false;
    const token = String(req.headers['x-devguard-token'] || '');
    return safeEqual(token, String(secret));
}

/** Signs an `/asset/` base URL and extension identity with HMAC-SHA256. */
function signAssetBase(secret, { decodedBase, publisher, name, version, platform }) {
    const cleanBase = String(decodedBase || '').replace(/\/+$/, '');
    const payload = `${cleanBase}|${String(publisher || '').toLowerCase()}|${String(name || '').toLowerCase()}|${version || 'latest'}|${platform || 'universal'}`;
    const mac = crypto.createHmac('sha256', String(secret)).update(payload).digest('base64url').slice(0, 22);
    const enc = Buffer.from(cleanBase, 'utf8').toString('base64url');
    return `${mac}.${enc}`;
}

/** Decodes `encBase` (supporting both signed `<mac>.<base64url>` and legacy `<base64url>`) and validates its host/path. */
function decodeAndVerifyAssetBase(encBase, { secret, publisher, name, version, platform, upstreamServiceUrl, proxyOrigin }) {
    const raw = String(encBase || '');
    const dot = raw.indexOf('.');
    let b64 = raw;
    let sig = null;
    if (dot > 0) {
        sig = raw.slice(0, dot);
        b64 = raw.slice(dot + 1);
    }
    let decodedBase = '';
    try { decodedBase = Buffer.from(b64, 'base64url').toString('utf8').replace(/\/+$/, ''); }
    catch (_e) { return null; }
    if (!decodedBase || decodedBase.startsWith(proxyOrigin)) return null;

    if (sig !== null) {
        const expected = signAssetBase(secret, { decodedBase, publisher, name, version, platform });
        if (!safeEqual(raw, expected)) return null;
    }

    if (!isAllowedAssetBaseUrl(decodedBase, { upstreamServiceUrl, publisher, name })) return null;
    return decodedBase;
}

/** Validates that `decodedBase` points to a trusted gallery CDN and matches `publisher/name`. */
function isAllowedAssetBaseUrl(decodedBase, { upstreamServiceUrl, publisher, name } = {}) {
    let parsed;
    try { parsed = new URL(decodedBase); } catch (_e) { return false; }
    const host = parsed.hostname.toLowerCase();
    const isLoopback = host === '127.0.0.1' || host === 'localhost';

    let hostAllowed = false;
    if (isLoopback) {
        hostAllowed = parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } else if (parsed.protocol === 'https:') {
        hostAllowed = TRUSTED_GALLERY_HOSTS.some(h => (h.startsWith('.') ? host.endsWith(h) : host === h));
        if (!hostAllowed && upstreamServiceUrl) {
            try { hostAllowed = new URL(upstreamServiceUrl).hostname.toLowerCase() === host; } catch (_e) { /* ignore */ }
        }
    }
    if (!hostAllowed) return false;

    if (publisher && name) {
        const lowerPath = decodeURIComponent(parsed.pathname).toLowerCase();
        const expectedPair = `/${String(publisher).toLowerCase()}/${String(name).toLowerCase()}`;
        if (!lowerPath.includes(expectedPair)) return false;
    }
    return true;
}

/** Verifies that a downloaded VSIX buffer matches `scan.sha256` when available. */
function verifyVsixSha256(buffer, expectedSha256) {
    if (typeof expectedSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(expectedSha256)) return true;
    const actual = crypto.createHash('sha256').update(buffer).digest('hex');
    return actual.toLowerCase() === expectedSha256.toLowerCase();
}

module.exports = {
    MAX_BODY_BYTES,
    loadOrCreateProxySecret,
    safeEqual,
    computeHandshakeMac,
    verifyPeerServer,
    isAllowedHost,
    isAllowedOrigin,
    isInternalPeerAuthorized,
    signAssetBase,
    decodeAndVerifyAssetBase,
    isAllowedAssetBaseUrl,
    verifyVsixSha256
};
