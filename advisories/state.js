/**
 * Persistent sync state and pointer management for pkgscan.dev advisories.
 *
 * Why this file exists:
 *   Users may close their editor for days or weeks. When they reopen it,
 *   DevGuard needs to know the exact advisory it last processed so it never
 *   misses advisories published while the editor was closed.
 *
 * How it works:
 *   - We store a small state object in `context.globalState`.
 *   - `pointer` holds `{ updatedAt, id }` of the newest processed advisory.
 *   - The pointer only moves forward after a successful merge. It never
 *     moves on network errors or partial fetches.
 *   - When resuming, we subtract a 10-minute overlap window from the pointer.
 *     This guards against clock skew, timestamp ties, and late database rows.
 *   - If the pointer is missing, corrupt, or older than 14 days, or if 24 hours
 *     have passed since the last full sync, we fall back to a full resync.
 */

const SYNC_STATE_KEY = 'devGuard.advisorySyncState';

// Overlap window subtracted from the pointer when resuming incremental sync.
const OVERLAP_MS = 10 * 60 * 1000; // 10 minutes

// Full resync every 24 hours so withdrawn advisories drop out of the cache.
const FULL_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

// If the extension was closed for more than 14 days, do a full resync.
const MAX_GAP_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

// Safety valve: if incremental paging takes more than 10 pages, do a full sync.
const MAX_INCREMENTAL_PAGES = 10;

/**
 * Parses an ISO date string into milliseconds since epoch.
 * Returns NaN when the input is not a valid date string.
 * @param {string|null|undefined} value
 * @returns {number}
 */
function timestampValue(value) {
    if (typeof value !== 'string') {
        return NaN;
    }
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? ms : NaN;
}

/**
 * Returns a clean default sync state object.
 * Used on first run or when stored state is unreadable.
 */
function defaultSyncState() {
    return {
        pointer: null,
        lastSuccessAt: 0,
        lastFullSyncAt: 0,
        etag: null,
        minWaitMs: 0,
        failureCount: 0
    };
}

/**
 * Checks whether a pointer object has a valid ISO timestamp and a non-empty ID.
 * @param {any} pointer
 * @returns {boolean}
 */
function isValidPointer(pointer) {
    if (!pointer || typeof pointer !== 'object') {
        return false;
    }
    if (typeof pointer.id !== 'string' || pointer.id.trim() === '') {
        return false;
    }
    return Number.isFinite(timestampValue(pointer.updatedAt));
}

/**
 * Reads the sync state from VS Code globalState.
 * Never throws: a bad or corrupt state returns a clean default state,
 * which triggers a safe full resync.
 * @param {any} context
 */
function loadSyncState(context) {
    const base = defaultSyncState();
    try {
        const raw = context && context.globalState
            ? context.globalState.get(SYNC_STATE_KEY)
            : null;
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        return {
            pointer: isValidPointer(raw.pointer)
                ? { updatedAt: raw.pointer.updatedAt, id: raw.pointer.id }
                : null,
            lastSuccessAt: Number.isFinite(raw.lastSuccessAt) && raw.lastSuccessAt > 0 ? raw.lastSuccessAt : 0,
            lastFullSyncAt: Number.isFinite(raw.lastFullSyncAt) && raw.lastFullSyncAt > 0 ? raw.lastFullSyncAt : 0,
            etag: typeof raw.etag === 'string' && raw.etag ? raw.etag : null,
            minWaitMs: Number.isFinite(raw.minWaitMs) && raw.minWaitMs >= 0 ? raw.minWaitMs : 0,
            failureCount: Number.isFinite(raw.failureCount) && raw.failureCount >= 0 ? raw.failureCount : 0
        };
    } catch (error) {
        console.warn('Could not read advisory sync state; resetting:', error);
        return base;
    }
}

/**
 * Saves the sync state to VS Code globalState.
 * Catches storage errors so a disk issue never crashes the audit loop.
 * @param {any} context
 * @param {ReturnType<typeof defaultSyncState>} state
 */
function saveSyncState(context, state) {
    try {
        if (context && context.globalState) {
            void context.globalState.update(SYNC_STATE_KEY, state);
        }
    } catch (error) {
        console.warn('Could not save advisory sync state:', error);
    }
}

/**
 * Decides whether we must run a full resync instead of an incremental poll.
 * We force a full sync when:
 *   1. There are no cached advisory entries on disk.
 *   2. The pointer is missing or invalid.
 *   3. More than 14 days have passed since the last successful sync.
 *   4. More than 24 hours have passed since the last full resync.
 * @param {ReturnType<typeof defaultSyncState>} state
 * @param {number} [now]
 * @param {boolean} [hasCachedEntries]
 * @returns {boolean}
 */
function shouldForceFullSync(state, now = Date.now(), hasCachedEntries = true) {
    if (!hasCachedEntries || !state || !isValidPointer(state.pointer)) {
        return true;
    }
    if (!state.lastSuccessAt || (now - state.lastSuccessAt) > MAX_GAP_MS) {
        return true;
    }
    if (!state.lastFullSyncAt || (now - state.lastFullSyncAt) > FULL_SYNC_INTERVAL_MS) {
        return true;
    }
    return false;
}

/**
 * Returns the timestamp (in ms) where incremental paging can safely stop.
 * Subtracting 10 minutes protects against ties and slightly out-of-order rows.
 * @param {{updatedAt: string, id: string}|null} pointer
 * @returns {number}
 */
function getOverlapCutoffMs(pointer) {
    if (!isValidPointer(pointer)) {
        return NaN;
    }
    return timestampValue(pointer.updatedAt) - OVERLAP_MS;
}

/**
 * Checks if an advisory item is at or older than the pointer's overlap window.
 * @param {{updatedAt?: string|null}} item
 * @param {{updatedAt: string, id: string}|null} pointer
 * @returns {boolean}
 */
function hasReachedPointer(item, pointer) {
    const cutoff = getOverlapCutoffMs(pointer);
    const itemMs = item ? timestampValue(item.updatedAt) : NaN;
    if (!Number.isFinite(cutoff) || !Number.isFinite(itemMs)) {
        return false;
    }
    return itemMs <= cutoff;
}

/**
 * Picks the newest `{ updatedAt, id }` pointer across existing state and new items.
 * Ties on `updatedAt` are broken by lexicographical `id` comparison for stability.
 * @param {{updatedAt: string, id: string}|null} currentPointer
 * @param {Array<{id?: string|null, extensionId?: string, version?: string, updatedAt?: string|null}>} items
 * @returns {{updatedAt: string, id: string}|null}
 */
function pickNewestPointer(currentPointer, items) {
    let best = isValidPointer(currentPointer) ? currentPointer : null;
    let bestMs = best ? timestampValue(best.updatedAt) : -Infinity;

    for (const item of Array.isArray(items) ? items : []) {
        if (!item) continue;
        const itemMs = timestampValue(item.updatedAt);
        const itemId = item.id || (item.extensionId ? `${item.extensionId}@${item.version || '*'}` : '');
        if (!Number.isFinite(itemMs) || !itemId) continue;

        if (itemMs > bestMs || (itemMs === bestMs && (!best || String(itemId) > String(best.id)))) {
            best = { updatedAt: item.updatedAt, id: String(itemId) };
            bestMs = itemMs;
        }
    }
    return best;
}

/**
 * Returns an updated state after a successful sync.
 * Advances the pointer, resets failureCount to 0, and records ETag / minWaitMs.
 */
function recordSyncSuccess(state, { items = [], full = false, etag, minWaitMs, now = Date.now() } = {}) {
    const base = state || defaultSyncState();
    const seedPointer = full ? null : base.pointer;
    const nextPointer = pickNewestPointer(seedPointer, items) || base.pointer;
    return {
        pointer: nextPointer,
        lastSuccessAt: now,
        lastFullSyncAt: full ? now : (base.lastFullSyncAt || now),
        etag: etag !== undefined ? etag : base.etag,
        minWaitMs: Number.isFinite(minWaitMs) && minWaitMs >= 0 ? minWaitMs : 0,
        failureCount: 0
    };
}

/**
 * Returns an updated state after a failed sync.
 * Keeps the pointer and timestamps untouched and increments failureCount.
 */
function recordSyncFailure(state) {
    const base = state || defaultSyncState();
    return {
        ...base,
        failureCount: (base.failureCount || 0) + 1
    };
}

module.exports = {
    SYNC_STATE_KEY,
    OVERLAP_MS,
    FULL_SYNC_INTERVAL_MS,
    MAX_GAP_MS,
    MAX_INCREMENTAL_PAGES,
    timestampValue,
    defaultSyncState,
    isValidPointer,
    loadSyncState,
    saveSyncState,
    shouldForceFullSync,
    getOverlapCutoffMs,
    hasReachedPointer,
    pickNewestPointer,
    recordSyncSuccess,
    recordSyncFailure
};
