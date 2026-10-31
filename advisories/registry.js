/**
 * Marketplace registry detection and per-extension provenance matching.
 *
 * Why this file exists:
 *   pkgscan.dev tracks advisories across multiple extension registries
 *   (`vscode-marketplace`, `cursor-marketplace`, `open-vsx`). An extension ID
 *   on one marketplace could be published by a different author on another.
 *   We want to match each installed extension against the marketplace it
 *   actually came from, without missing sideloaded `.vsix` extensions.
 *
 * How we find the marketplace:
 *   1. The editor's `product.json` (inside `vscode.env.appRoot`) contains
 *      `extensionsGallery.serviceUrl`. We map its hostname to a pkgscan
 *      registry slug. If `product.json` cannot be read, we fall back to
 *      `vscode.env.appName`.
 *   2. The editor's `extensions.json` (in the parent folder of each installed
 *      extension) records `metadata.source` (`"gallery"`, `"vsix"`, or
 *      `"resource"`).
 *   3. Gallery-installed extensions only match advisories from the editor's
 *      registry (plus registry-agnostic community blocklist entries).
 *      Sideloaded VSIX or unknown-source extensions match all registries.
 */

const fs = require('fs');
const path = require('path');

// Known gallery hostnames mapped to pkgscan.dev registry slugs.
// Confirmed against pkgscan.dev/api/advisories: Open VSX uses slug `openvsx` (923 advisories).
const HOST_TO_REGISTRY = [
    { match: 'marketplace.visualstudio.com', registry: 'vscode-marketplace' },
    { match: 'marketplace.cursorapi.com', registry: 'cursor-marketplace' },
    { match: 'open-vsx.org', registry: 'openvsx' }
];

// Fallback mapping when product.json is unavailable.
const APP_NAME_TO_REGISTRY = [
    { match: 'cursor', registry: 'cursor-marketplace' },
    { match: 'visual studio code', registry: 'vscode-marketplace' },
    { match: 'vscodium', registry: 'openvsx' },
    { match: 'windsurf', registry: 'openvsx' },
    { match: 'positron', registry: 'openvsx' },
    { match: 'codium', registry: 'openvsx' }
];

/**
 * Normalizes a registry slug so `open-vsx` and `openvsx` are treated identically.
 * @param {string|null|undefined} slug
 * @returns {string|null}
 */
function normalizeRegistrySlug(slug) {
    if (!slug || typeof slug !== 'string') return null;
    const lower = slug.trim().toLowerCase();
    if (!lower) return null;
    if (lower === 'open-vsx') return 'openvsx';
    return lower;
}

/**
 * Maps a `product.json` gallery serviceUrl or galleryId to a pkgscan registry.
 * Returns null if the gallery URL is unknown.
 * @param {{serviceUrl?: string, galleryId?: string}|null|undefined} gallery
 * @returns {string|null}
 */
function registryFromGalleryConfig(gallery) {
    if (!gallery || typeof gallery !== 'object') {
        return null;
    }
    const serviceUrl = String(gallery.serviceUrl || '').toLowerCase();
    for (const entry of HOST_TO_REGISTRY) {
        if (serviceUrl.includes(entry.match)) {
            return entry.registry;
        }
    }
    const galleryId = String(gallery.galleryId || '').toLowerCase();
    if (galleryId === 'cursor') return 'cursor-marketplace';
    if (galleryId === 'vscode') return 'vscode-marketplace';
    if (galleryId === 'openvsx' || galleryId === 'open-vsx') return 'openvsx';
    return null;
}

/**
 * Resolves the active editor's marketplace registry.
 * First checks `product.json` under `appRoot`, then falls back to `appName`.
 * Returns null when the editor cannot be identified (no filtering applied).
 * @param {{appRoot?: string, appName?: string, uriScheme?: string, readFileSync?: Function}} [env]
 * @returns {{registry: string|null, method: 'product.json'|'appName'|'unknown'}}
 */
function resolveEditorRegistry(env = {}) {
    const read = env.readFileSync || fs.readFileSync;
    if (typeof env.appRoot === 'string' && env.appRoot.length > 0) {
        try {
            const productPath = path.join(env.appRoot, 'product.json');
            const parsed = JSON.parse(read(productPath, 'utf8'));
            const fromGallery = registryFromGalleryConfig(parsed && parsed.extensionsGallery);
            if (fromGallery) {
                return { registry: fromGallery, method: 'product.json' };
            }
        } catch (_error) {
            // Fall back to appName when product.json is missing or unreadable.
        }
    }

    const label = `${env.appName || ''} ${env.uriScheme || ''}`.toLowerCase();
    for (const entry of APP_NAME_TO_REGISTRY) {
        if (label.includes(entry.match)) {
            return { registry: entry.registry, method: 'appName' };
        }
    }

    return { registry: null, method: 'unknown' };
}

/**
 * Reads `extensions.json` from the user's extensions directory to find each
 * extension's install source (`"gallery"`, `"vsix"`, `"resource"`, or `"unknown"`)
 * and targetPlatform.
 * @param {Array<any>} extensions List from `vscode.extensions.all`
 * @param {{readFileSync?: Function}} [options]
 * @returns {Map<string, {source: string, targetPlatform: string|null, uuid: string|null}>}
 */
function loadExtensionProvenance(extensions, options = {}) {
    const read = options.readFileSync || fs.readFileSync;
    const provenance = new Map();
    const seenManifestDirs = new Set();

    for (const ext of Array.isArray(extensions) ? extensions : []) {
        if (!ext || typeof ext.extensionPath !== 'string' || !ext.extensionPath) {
            continue;
        }
        // Skip built-in extensions that live inside the editor's appRoot.
        if (ext.packageJSON && ext.packageJSON.isBuiltin) {
            continue;
        }
        const parentDir = path.dirname(ext.extensionPath);
        if (seenManifestDirs.has(parentDir)) {
            continue;
        }
        seenManifestDirs.add(parentDir);

        try {
            const manifestPath = path.join(parentDir, 'extensions.json');
            const list = JSON.parse(read(manifestPath, 'utf8'));
            if (!Array.isArray(list)) continue;

            for (const item of list) {
                const id = item && item.identifier && typeof item.identifier.id === 'string'
                    ? item.identifier.id.toLowerCase()
                    : null;
                if (!id) continue;
                const meta = (item && item.metadata) || {};
                provenance.set(id, {
                    source: typeof meta.source === 'string' && meta.source ? meta.source.toLowerCase() : 'unknown',
                    targetPlatform: typeof meta.targetPlatform === 'string' ? meta.targetPlatform : null,
                    uuid: (item.identifier && item.identifier.uuid) || meta.id || null
                });
            }
        } catch (_error) {
            // Missing or unreadable extensions.json leaves entries as unknown source.
        }
    }

    return provenance;
}

/**
 * Checks whether an advisory platform matches an installed extension's platform.
 * Universal / default / wildcard platforms match every build.
 * @param {string|null|undefined} advisoryPlatform
 * @param {string|null|undefined} installedPlatform
 * @returns {boolean}
 */
function isPlatformMatch(advisoryPlatform, installedPlatform) {
    const adv = String(advisoryPlatform || '').toLowerCase();
    if (!adv || adv === '*' || adv === 'default' || adv === 'universal' || adv === 'undefined') {
        return true;
    }
    const inst = String(installedPlatform || '').toLowerCase();
    if (!inst || inst === 'universal' || inst === 'undefined') {
        return true;
    }
    return adv === inst;
}

/**
 * Checks whether a single advisory entry applies to an installed extension
 * given the editor's registry and the extension's provenance.
 * @param {{registry?: string|null, platform?: string|null}} advisoryEntry
 * @param {any} extension
 * @param {{source?: string, targetPlatform?: string|null}|undefined} extProvenance
 * @param {string|null} editorRegistry
 * @returns {boolean}
 */
function isRegistryAndPlatformMatch(advisoryEntry, extension, extProvenance, editorRegistry) {
    const installedPlatform = (extProvenance && extProvenance.targetPlatform)
        || (extension && extension.packageJSON && extension.packageJSON.__metadata && extension.packageJSON.__metadata.targetPlatform)
        || null;

    if (!isPlatformMatch(advisoryEntry.platform, installedPlatform)) {
        return false;
    }

    // Community blocklist entries have no specific registry (`null` or `'*'`)
    // and always apply.
    const advisoryRegistry = normalizeRegistrySlug(advisoryEntry.registry);
    if (!advisoryRegistry || advisoryRegistry === '*') {
        return true;
    }

    // If we don't know the editor's registry, or if the extension was sideloaded
    // from a VSIX / unknown source, match advisories from all registries.
    const source = extProvenance && extProvenance.source ? extProvenance.source : 'unknown';
    const normalizedEditor = normalizeRegistrySlug(editorRegistry);
    if (!normalizedEditor || source !== 'gallery') {
        return true;
    }

    return advisoryRegistry === normalizedEditor;
}

module.exports = {
    HOST_TO_REGISTRY,
    APP_NAME_TO_REGISTRY,
    normalizeRegistrySlug,
    registryFromGalleryConfig,
    resolveEditorRegistry,
    loadExtensionProvenance,
    isPlatformMatch,
    isRegistryAndPlatformMatch
};
