/**
 * Incremental and full sync client for pkgscan.dev advisories.
 *
 * Key behaviours:
 *   - Routine 5-minute polls fetch a small page (`limit=20`) with `If-None-Match`
 *     (ETag) and `updatedSince`, paging deeper only when every item on the page
 *     is newer than our persisted pointer (minus a 10-minute overlap).
 *   - If incremental paging exceeds `MAX_INCREMENTAL_PAGES` or the pointer is
 *     older than 14 days / 24h full-sync interval, we run a full resync.
 *   - Items with `withdrawn: true` remove matching entries during merge.
 *   - Advisories with `windows[].state === "REMOVED"` are kept because an
 *     already-installed copy on disk remains dangerous until uninstalled.
 */

const {
    MAX_INCREMENTAL_PAGES,
    getOverlapCutoffMs,
    hasReachedPointer,
    loadSyncState,
    saveSyncState,
    shouldForceFullSync,
    recordSyncSuccess,
    recordSyncFailure
} = require('./state');

const PKGSCAN_ADVISORIES_URL = 'https://www.pkgscan.dev/api/advisories';
const PKGSCAN_FULL_PAGE_SIZE = 100;
const PKGSCAN_POLL_PAGE_SIZE = 20;
const PKGSCAN_FETCH_TIMEOUT_MS = 15000;
const PKGSCAN_MAX_ATTEMPTS = 4;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Normalizes one pkgscan advisory item into the internal audit entry shape.
 * Re-checks `ecosystem` and `registry` client-side. Keeps `REMOVED` advisories
 * and records their takedown timestamp so notifications can show it.
 * @param {any} item
 * @param {{allowedRegistries?: string[]|null}} [options]
 */
function toAdvisoryEntry(item, options = {}) {
    if (!item || item.ecosystem !== 'vscode-extension') {
        return null;
    }
    const rawRegistry = typeof item.registry === 'string' && item.registry ? item.registry.toLowerCase() : null;
    const registry = rawRegistry === 'open-vsx' ? 'openvsx' : rawRegistry;
    if (Array.isArray(options.allowedRegistries) && options.allowedRegistries.length > 0 && registry) {
        const allowed = options.allowedRegistries.map(r => {
            const s = String(r).toLowerCase();
            return s === 'open-vsx' ? 'openvsx' : s;
        });
        if (!allowed.includes(registry)) {
            return null;
        }
    }

    const publisher = typeof item.namespace === 'string' ? item.namespace.trim() : '';
    const name = typeof item.name === 'string' ? item.name.trim() : '';
    if (!publisher || !name) {
        return null;
    }

    const permalink = typeof item.permalink === 'string' && item.permalink.startsWith('/')
        ? `https://www.pkgscan.dev${item.permalink}`
        : (typeof item.referenceUrl === 'string' && item.referenceUrl.startsWith('http') ? item.referenceUrl : null);

    const win = Array.isArray(item.windows) && item.windows[0] ? item.windows[0] : null;
    return {
        id: typeof item.id === 'string' ? item.id : null,
        extensionId: `${publisher}.${name}`,
        version: typeof item.version === 'string' && item.version ? item.version : '*',
        registry,
        platform: typeof item.platform === 'string' && item.platform ? item.platform : 'universal',
        severity: item.severity || null,
        title: item.title || null,
        summary: item.summary || null,
        permalink,
        updatedAt: typeof item.updatedAt === 'string' ? item.updatedAt : null,
        firstSeenAt: typeof item.firstSeenAt === 'string' ? item.firstSeenAt : null,
        windowState: win && typeof win.state === 'string' ? win.state : null,
        takenDownAt: win && typeof win.takenDownAt === 'string' ? win.takenDownAt : null,
        withdrawn: Boolean(item.withdrawn || item.status === 'withdrawn')
    };
}

/**
 * Builds the pkgscan query URL with forward-compatible filter parameters.
 */
function buildAdvisoriesUrl({ baseUrl = PKGSCAN_ADVISORIES_URL, limit, offset = 0, registry = null, updatedSince = null, after = null }) {
    const params = new URLSearchParams({
        kind: 'malicious',
        ecosystem: 'vscode-extension',
        limit: String(limit),
        offset: String(offset)
    });
    if (registry) params.set('registry', registry);
    if (updatedSince) params.set('updatedSince', updatedSince);
    if (after) params.set('after', after);
    return `${baseUrl}?${params.toString()}`;
}

/**
 * Fetches one page of advisories with ETag (`If-None-Match`), rate-limit retries,
 * and server `X-Min-Poll-Seconds` parsing.
 */
async function fetchPageWithMeta(url, { etag = null, fetchImpl = fetch, timeoutMs = PKGSCAN_FETCH_TIMEOUT_MS } = {}, attempt = 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const headers = { accept: 'application/json' };
    if (etag) headers['if-none-match'] = etag;

    let response;
    try {
        response = await fetchImpl(url, { headers, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }

    if (response.status === 429 && attempt < PKGSCAN_MAX_ATTEMPTS) {
        const retryAfter = Number(response.headers && response.headers.get && response.headers.get('retry-after'));
        const delay = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 1000 * Math.pow(2, attempt - 1);
        await sleep(delay);
        return fetchPageWithMeta(url, { etag, fetchImpl, timeoutMs }, attempt + 1);
    }
    if (response.status >= 500 && attempt < PKGSCAN_MAX_ATTEMPTS) {
        await sleep(500 * attempt);
        return fetchPageWithMeta(url, { etag, fetchImpl, timeoutMs }, attempt + 1);
    }

    const getHeader = name => (response.headers && typeof response.headers.get === 'function' ? response.headers.get(name) : null);
    const responseEtag = getHeader('etag') || etag;
    const minPollSec = Number(getHeader('x-min-poll-seconds'));
    const headerMinWaitMs = Number.isFinite(minPollSec) && minPollSec > 0 ? minPollSec * 1000 : 0;

    if (response.status === 304) {
        return { notModified: true, data: null, etag: responseEtag, minWaitMs: headerMinWaitMs };
    }
    if (!response.ok) {
        throw new Error(`Request failed: ${response.status} ${response.statusText || ''}`.trim());
    }

    const data = await response.json();
    const bodyMinWaitMs = data && Number.isFinite(Number(data.minimumWaitMs)) ? Number(data.minimumWaitMs) : 0;
    return { notModified: false, data, etag: responseEtag, minWaitMs: Math.max(headerMinWaitMs, bodyMinWaitMs) };
}

/**
 * Merges fresh advisory entries into existing ones by stable advisory key.
 * Removes entries marked `withdrawn: true` so false positives can be retracted.
 */
function mergeAdvisories(existing, fresh) {
    const map = new Map();
    const keyOf = entry => entry.id || `${entry.registry || '*'}:${entry.extensionId.toLowerCase()}@${entry.version}:${entry.platform || 'universal'}`;
    for (const entry of Array.isArray(existing) ? existing : []) {
        if (entry && !entry.withdrawn) map.set(keyOf(entry), entry);
    }
    for (const entry of Array.isArray(fresh) ? fresh : []) {
        if (!entry) continue;
        const key = keyOf(entry);
        if (entry.withdrawn) map.delete(key);
        else map.set(key, entry);
    }
    return Array.from(map.values());
}

/**
 * Fetches advisories from pkgscan.dev (either incremental since pointer or full).
 */
async function fetchPkgscanAdvisories({ pointer = null, full = true, registry = null, etag = null, baseUrl = PKGSCAN_ADVISORIES_URL, fetchImpl = fetch } = {}) {
    const limit = full ? PKGSCAN_FULL_PAGE_SIZE : PKGSCAN_POLL_PAGE_SIZE;
    const cutoffMs = !full && pointer ? getOverlapCutoffMs(pointer) : NaN;
    const updatedSince = Number.isFinite(cutoffMs) ? new Date(cutoffMs).toISOString() : null;
    const allowedRegistries = registry ? registry.split(',').map(s => s.trim()).filter(Boolean) : null;

    const firstUrl = buildAdvisoriesUrl({ baseUrl, limit, offset: 0, registry, updatedSince });
    const first = await fetchPageWithMeta(firstUrl, { etag: full ? null : etag, fetchImpl });
    if (first.notModified) {
        return { notModified: true, entries: [], rawItems: [], complete: true, etag: first.etag, minWaitMs: first.minWaitMs };
    }

    const entries = [];
    const rawItems = [];
    let reachedPointer = false;
    let scannedPages = 0;

    const collect = items => {
        for (const item of items) {
            if (item) rawItems.push(item);
            if (!full && pointer && hasReachedPointer(item, pointer)) {
                reachedPointer = true;
                const entry = toAdvisoryEntry(item, { allowedRegistries });
                if (entry) entries.push(entry);
                return false;
            }
            const entry = toAdvisoryEntry(item, { allowedRegistries });
            if (entry) entries.push(entry);
        }
        return true;
    };

    const firstItems = Array.isArray(first.data && first.data.items) ? first.data.items : [];
    const total = Number.isFinite(Number(first.data && first.data.total)) ? Number(first.data.total) : firstItems.length;
    let keepGoing = collect(firstItems);
    scannedPages++;
    let offset = firstItems.length;
    let after = first.data && typeof first.data.nextCursor === 'string' ? first.data.nextCursor : null;

    while (keepGoing && offset < total) {
        if (!full && scannedPages >= MAX_INCREMENTAL_PAGES) {
            return { notModified: false, entries, rawItems, complete: false, exceededPageLimit: true, etag: first.etag, minWaitMs: first.minWaitMs };
        }
        await sleep(50);
        const pageUrl = buildAdvisoriesUrl({ baseUrl, limit, offset, registry, updatedSince, after });
        const page = await fetchPageWithMeta(pageUrl, { fetchImpl });
        const items = Array.isArray(page.data && page.data.items) ? page.data.items : [];
        if (items.length === 0) break;
        keepGoing = collect(items);
        scannedPages++;
        offset += items.length;
        after = page.data && typeof page.data.nextCursor === 'string' ? page.data.nextCursor : null;
    }

    return { notModified: false, entries, rawItems, complete: true, reachedPointer, scannedPages, etag: first.etag, minWaitMs: first.minWaitMs };
}

module.exports = {
    PKGSCAN_ADVISORIES_URL,
    PKGSCAN_FULL_PAGE_SIZE,
    PKGSCAN_POLL_PAGE_SIZE,
    toAdvisoryEntry,
    buildAdvisoriesUrl,
    fetchPageWithMeta,
    mergeAdvisories,
    fetchPkgscanAdvisories
};
