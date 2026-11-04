/**
 * Fetches pkgscan.dev package scan data and injects a security header into
 * extension READMEs served through the local marketplace proxy.
 *
 * Why this file exists:
 *   When a user clicks an extension in the Extensions view, VS Code requests
 *   its `Microsoft.VisualStudio.Services.Content.Details` (README) asset.
 *   We intercept that request and prepend a compact security summary from
 *   `pkgscan.dev/api/pkg/vscode-extension/...` plus a prominent warning
 *   banner when the extension matches a security advisory or a blocking scan
 *   verdict. The whole block is a GitHub alert (`[!NOTE]`, `[!WARNING]`,
 *   or `[!CAUTION]`). A flagged extension also gets a nested caution box.
 *   START/END headings are not used.
 *
 * Underlying marketplace & PURL accuracy:
 *   - Extensions served from Open VSX (`open-vsx.org`) or Cursor's Open VSX
 *     mirror (`marketplace.cursorapi.com/open-vsx-mirror/...`) have Open VSX
 *     metadata and must include `?repository_url=https%3A%2F%2Fopen-vsx.org`
 *     in their PURL, API lookup, badge URL, and pkgscan.dev report/scan link.
 *   - Extensions served from Visual Studio Marketplace (`marketplace.visualstudio.com`
 *     or `*.vsassets.io`) use the default pkgscan.dev PURL without `repository_url`.
 */

const DEFAULT_PKGSCAN_BASE_URL = 'https://www.pkgscan.dev';
const OPENVSX_REPOSITORY_URL = 'https://open-vsx.org';
const SCAN_TIMEOUT_MS = 2500;
const CACHE_TTL_MS = 10 * 60 * 1000;
const MAX_CACHE_ENTRIES = 200;

/**
 * Determines the pkgscan.dev `repository_url` qualifier for an extension based
 * on its upstream asset URL (`assetBaseUrl`) and gallery `registry` slug.
 * Returns `'https://open-vsx.org'` for Open VSX (including Cursor's Open VSX
 * mirror) and `null` for the Microsoft Visual Studio Marketplace default.
 */
function resolveRepositoryUrl({ registry, assetBaseUrl } = {}) {
    const base = String(assetBaseUrl || '').toLowerCase();
    if (base.includes('vsassets.io') || base.includes('marketplace.visualstudio.com')) {
        return null;
    }
    if (base.includes('open-vsx.org') || base.includes('openvsx.org') || base.includes('/open-vsx-mirror')) {
        return OPENVSX_REPOSITORY_URL;
    }
    const reg = String(registry || '').trim().toLowerCase();
    if (reg === 'openvsx' || reg === 'open-vsx' || reg === 'cursor-marketplace') {
        return OPENVSX_REPOSITORY_URL;
    }
    return null;
}

/**
 * Builds the canonical PURL and pkgscan.dev API / badge / web URLs for an
 * extension version, preserving `repository_url` for Open VSX packages.
 */
function buildPkgscanUrls({ publisher, name, version, registry, assetBaseUrl, baseUrl = DEFAULT_PKGSCAN_BASE_URL }) {
    const cleanBase = String(baseUrl || DEFAULT_PKGSCAN_BASE_URL).replace(/\/+$/, '');
    const normPub = String(publisher || '').trim().toLowerCase();
    const normExt = String(name || '').trim().toLowerCase();
    const pub = encodeURIComponent(normPub);
    const ext = encodeURIComponent(normExt);
    const hasVer = Boolean(version && version !== 'latest');
    const ver = hasVer ? `@${encodeURIComponent(version)}` : '';
    const repositoryUrl = resolveRepositoryUrl({ registry, assetBaseUrl });
    const repoQuery = repositoryUrl ? `?repository_url=${encodeURIComponent(repositoryUrl)}` : '';
    const purl = `pkg:vscode-extension/${normPub}/${normExt}${hasVer ? `@${version}` : ''}${repoQuery}`;

    return {
        purl,
        repositoryUrl,
        apiUrl: `${cleanBase}/api/pkg/vscode-extension/${pub}/${ext}${ver}${repoQuery}`,
        fallbackApiUrl: `${cleanBase}/api/pkg/vscode-extension/${pub}/${ext}${repoQuery}`,
        badgeUrl: `${cleanBase}/api/badge/vscode-extension/${pub}/${ext}${hasVer ? `%40${encodeURIComponent(version)}` : ''}${repoQuery}`,
        reportUrl: `${cleanBase}/pkg/vscode-extension/${pub}/${ext}${ver}${repoQuery}`
    };
}

/** Fetches JSON from a URL with a strict abort timeout. Returns null on error. */
async function fetchJsonQuick(url, { fetchImpl = fetch, timeoutMs = SCAN_TIMEOUT_MS } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timer?.unref === 'function') timer.unref();
    try {
        const res = await fetchImpl(url, { headers: { accept: 'application/json' }, signal: controller.signal });
        return res && res.ok ? await res.json() : null;
    } catch (_error) {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

/** Creates a cached scan fetcher for pkgscan.dev package metadata. */
function createScanFetcher({ baseUrl = DEFAULT_PKGSCAN_BASE_URL, fetchImpl = fetch, timeoutMs = SCAN_TIMEOUT_MS } = {}) {
    const cache = new Map();

    async function getScanData({ publisher, name, version, registry, assetBaseUrl }) {
        if (!publisher || !name) return null;
        const repoUrl = resolveRepositoryUrl({ registry, assetBaseUrl });
        const key = `${repoUrl || 'ms-marketplace'}:${publisher.toLowerCase()}.${name.toLowerCase()}@${version || 'latest'}`;
        const now = Date.now();
        const hit = cache.get(key);
        if (hit && hit.data && hit.data.status === 'completed' && (now - hit.at) < CACHE_TTL_MS) return hit.data;

        const urls = buildPkgscanUrls({ publisher, name, version, registry, assetBaseUrl, baseUrl });
        // Always query the exact marketplace (with repository_url for Open VSX).
        // Never fall back across marketplaces so Open VSX extensions never show
        // Microsoft Visual Studio Marketplace scan results or links.
        let data = await fetchJsonQuick(urls.apiUrl, { fetchImpl, timeoutMs });
        if ((!data || data.status === 'unscanned') && (!version || version === 'latest') && urls.fallbackApiUrl !== urls.apiUrl) {
            const fallbackData = await fetchJsonQuick(urls.fallbackApiUrl, { fetchImpl, timeoutMs });
            if (fallbackData && fallbackData.status === 'completed') data = fallbackData;
        }

        // Only cache completed scans (`status === 'completed'`). Never cache
        // `unscanned`, `queued`, `scanning`, or failed lookups so a package
        // that is scanned on pkgscan.dev after viewing its README is immediately
        // recognized and blocked on the next README view or Install click.
        if (data && data.status === 'completed') {
            if (cache.size >= MAX_CACHE_ENTRIES) {
                const oldestKey = cache.keys().next().value;
                if (oldestKey) cache.delete(oldestKey);
            }
            cache.set(key, { at: now, data });
        } else {
            cache.delete(key);
        }
        return data;
    }

    return { getScanData, clearCache: () => cache.clear() };
}

/**
 * Converts a `pkgscan.dev/api/pkg` scan response into an advisory-like object
 * when `flaggedCount > 0` or any security engine returned a `block` verdict.
 */
function scanBlockAdvisory(scan, { publisher, name, version, registry, assetBaseUrl, baseUrl = DEFAULT_PKGSCAN_BASE_URL } = {}) {
    if (!scan || scan.status !== 'completed') return null;
    const blockingEngines = (Array.isArray(scan.engines) ? scan.engines : []).filter(e => {
        const v = String(e && e.verdict || '').toLowerCase();
        return v === 'block' || v === 'malicious' || v === 'fail';
    });
    const flagged = Number(scan.flaggedCount) || 0;
    if (flagged <= 0 && blockingEngines.length === 0) return null;

    const urls = buildPkgscanUrls({ publisher, name, version, registry, assetBaseUrl, baseUrl });
    const names = blockingEngines.map(e => e.id).join(', ');
    return {
        id: `scan:${String(publisher || '').toLowerCase()}.${String(name || '').toLowerCase()}@${version || '*'}`,
        extensionId: `${publisher}.${name}`,
        version: version || '*',
        severity: 'high',
        title: names ? `Flagged as malicious by ${names}` : 'Flagged by pkgscan.dev security scan',
        permalink: urls.reportUrl
    };
}

/**
 * Turns revoked allowlist ids into live findings when pkgscan's engine scan
 * flagged them. The advisory feed does not list every blocked package
 * (Ackee's tools-for-solidity is one of those), so a revoke would otherwise
 * leave the next scan silent.
 * `skipIds` are extensions the advisory match already found.
 * `retry` are ids whose scan did not finish, so the caller should ask again.
 */
async function collectEngineThreats({ ids, extensions, allowlist, skipIds, registry, getScanData }) {
    const allow = allowlist instanceof Set ? allowlist : new Set();
    const skip = skipIds instanceof Set ? skipIds : new Set();
    const byId = new Map();
    for (const ext of Array.isArray(extensions) ? extensions : []) {
        if (ext && ext.id) byId.set(String(ext.id).toLowerCase(), ext);
    }
    const threats = [];
    const retry = [];
    // Completed lookups. The caller can remember a clean result and not ask again.
    const checked = [];
    for (const raw of Array.isArray(ids) ? ids : []) {
        const id = String(raw || '').toLowerCase();
        if (!id || allow.has(id) || skip.has(id)) continue;
        const ext = byId.get(id);
        if (!ext) continue;
        const dot = id.indexOf('.');
        if (dot <= 0) continue;
        const publisher = id.slice(0, dot);
        const name = id.slice(dot + 1);
        const version = ext.packageJSON && ext.packageJSON.version;
        let scan = null;
        try {
            scan = typeof getScanData === 'function'
                ? await getScanData({ publisher, name, version, registry })
                : null;
        } catch (_error) {
            scan = null;
        }
        // A failed or unfinished lookup is not "clean". Ask again next scan.
        if (!scan || scan.status !== 'completed') {
            retry.push(id);
            continue;
        }
        checked.push(id);
        const advisory = scanBlockAdvisory(scan, { publisher, name, version, registry });
        if (advisory) threats.push({ extension: ext, advisory });
    }
    return { threats, retry, checked };
}

function formatEngineVerdict(engine) {
    const v = String(engine && engine.verdict || '').toLowerCase();
    if (v === 'block' || v === 'malicious' || v === 'fail') return 'Malicious (block)';
    if (v === 'warn' || v === 'suspicious') return 'Suspicious (warn)';
    if (v === 'pass' || v === 'clean') return 'Clean (pass)';
    return engine && engine.status ? String(engine.status) : 'n/a';
}

/** Prefixes each line so the whole injection sits inside one GitHub alert box. */
function asAlert(kind, lines) {
    return [`> [!${kind}]`, ...lines.map(line => (line === '' ? '>' : `> ${line}`))].join('\n');
}

/** Nested alert lines. After `asAlert` wraps them they become `> > [!KIND]`. */
function nestedAlert(kind, lines) {
    return [`> [!${kind}]`, ...lines.map(line => (line === '' ? '>' : `> ${line}`))];
}

function formatScanHeader({ publisher, name, version, registry, assetBaseUrl, scan, advisory, allowlisted = false, baseUrl = DEFAULT_PKGSCAN_BASE_URL }) {
    const urls = buildPkgscanUrls({ publisher, name, version, registry, assetBaseUrl, baseUrl });
    const effectiveAdv = advisory || scanBlockAdvisory(scan, { publisher, name, version, registry, assetBaseUrl, baseUrl });
    // Always use `urls.reportUrl` for the package page link so the `repository_url`
    // query parameter matches the underlying marketplace when submitting/viewing a scan.
    const reportUrl = urls.reportUrl;
    const extId = `${publisher}.${name}${version ? `@${version}` : ''}`;

    // One alert around the injected block. A threat gets a second box inside it.
    const body = [
        'This block is added by [Yeeth Dev-Guard](https://yeethsecurity.com). It is **not** part of the publisher\'s README.'
    ];

    if (effectiveAdv) {
        const sev = String(effectiveAdv.severity || 'high').toUpperCase();
        const title = effectiveAdv.title ? String(effectiveAdv.title).replace(/[_-]+/g, ' ') : 'Malicious extension advisory';
        const statusNote = allowlisted
            ? 'This extension is on your `devGuard.allowlist`, so downloads are permitted.'
            : '**Download blocked by Dev-Guard.** This extension remains visible in search results, but VSIX downloads are blocked.';
        body.push(
            '',
            ...nestedAlert('CAUTION', [
                `### [DEV-GUARD SECURITY ADVISORY — ${sev}]`,
                `**${extId}** was flagged on [pkgscan.dev](${reportUrl}): **${title}**.`,
                statusNote
            ])
        );
    }

    body.push('', `[![pkgscan.dev](${urls.badgeUrl})](${reportUrl})`, '');
    if (scan && scan.status === 'completed') {
        const engines = (Array.isArray(scan.engines) ? scan.engines : []).filter(e => e && e.status !== 'unsupported');
        const flagged = Number(scan.flaggedCount) || 0;
        const analyzedDate = typeof scan.analyzedAt === 'string' ? scan.analyzedAt.slice(0, 10) : 'recent';
        const scannedVer = scan.extension && scan.extension.version ? scan.extension.version : (version || 'latest');
        const shaShort = typeof scan.sha256 === 'string' && scan.sha256.length >= 12 ? ` · SHA-256 \`${scan.sha256.slice(0, 12)}…\`` : '';
        const headline = flagged > 0 || effectiveAdv
            ? `**Flagged** (${flagged || 1} malware engine alert)`
            : `**No malware engines flagged** (${engines.length} engines checked)`;

        body.push(`**pkgscan.dev Security Scan** — ${headline} · v${scannedVer} · Analyzed ${analyzedDate}${shaShort} · PURL \`${urls.purl}\` · [Full report ↗](${reportUrl})`);
        if (engines.length > 0) {
            body.push('', '| Engine | Verdict | Findings |', '| :--- | :--- | :--- |');
            for (const eng of engines) {
                body.push(`| \`${eng.id}\` | ${formatEngineVerdict(eng)} | ${Number(eng.findingCount) || 0} |`);
            }
        }
    } else {
        const stateLabel = scan && scan.status ? scan.status : 'unscanned';
        const verdictNote = effectiveAdv ? '**Flagged by pkgscan.dev advisory**' : 'No active malicious advisory';
        body.push(`**pkgscan.dev Security Scan** — ${verdictNote} · Scan status: \`${stateLabel}\` · PURL \`${urls.purl}\` · [Scan on pkgscan.dev ↗](${reportUrl})`);
    }

    body.push(
        '',
        'The publisher\'s original README starts below this line.'
    );

    // A flagged package is a caution. A finished clean scan is a note.
    // Anything we could not scan is a warning.
    const outer = effectiveAdv ? 'CAUTION' : (scan && scan.status === 'completed' ? 'NOTE' : 'WARNING');
    return `${asAlert(outer, body)}\n\n---\n\n`;
}

function injectReadmeScanData(originalReadme, options) {
    return `${formatScanHeader(options)}${typeof originalReadme === 'string' ? originalReadme : ''}`;
}

module.exports = {
    DEFAULT_PKGSCAN_BASE_URL,
    OPENVSX_REPOSITORY_URL,
    resolveRepositoryUrl,
    buildPkgscanUrls,
    createScanFetcher,
    scanBlockAdvisory,
    collectEngineThreats,
    formatScanHeader,
    injectReadmeScanData
};
