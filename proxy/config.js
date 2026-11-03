/**
 * Marketplace configuration state and URL resolution for the local proxy.
 *
 * Why this file exists:
 *   When the Dev-Guard local proxy is turned on, we point the editor's
 *   marketplace configuration at our local `127.0.0.1` server. When the proxy
 *   is turned off (or uninstalled), we restore the exact marketplace
 *   configuration the user had beforehand.
 *
 * Multi-IDE & VS Code 1.144+ support:
 *   - Every IDE gets its own predefined loopback port (`45821` Cursor, `45822`
 *     VS Code, `45823` VSCodium, `45824` Windsurf, `45825` VS Code Insiders,
 *     `45826` Positron) so running multiple IDEs simultaneously never conflicts.
 *   - In VS Code 1.144+, `extensions.gallery.serviceUrl` is `included: false`
 *     and `workbench.html` has `connect-src 'self' https: ws:` (unlike Cursor,
 *     which includes `http:`). We patch `product.json#extensionsGallery` and
 *     add `http://127.0.0.1:*` to `workbench.html` (updating its SHA-256 in
 *     `product.json#checksums`), restoring everything byte-for-byte on disable/uninstall.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { registryFromGalleryConfig, resolveEditorRegistry, resolveEditorGalleryUrl } = require('../advisories/registry');
const { writeUninstallRestoreManifest } = require('./uninstall');

const PROXY_STATE_KEY = 'devGuard.proxyState';
const DEFAULT_PROXY_PORT = 45821;
const IDE_PROXY_PORTS = [
    { match: 'cursor', port: 45821 },
    { match: 'insiders', port: 45825 },
    { match: 'vscodium', port: 45823 },
    { match: 'codium', port: 45823 },
    { match: 'windsurf', port: 45824 },
    { match: 'positron', port: 45826 },
    { match: 'visual studio code', port: 45822 }
];
const REGISTRY_PROXY_PORTS = { 'cursor-marketplace': 45821, 'vscode-marketplace': 45822, openvsx: 45823 };
const PROXY_GALLERY_PATH = '/_apis/public/gallery';
const WORKBENCH_HTML_CANDIDATES = [
    'vs/code/electron-browser/workbench/workbench.html',
    'vs/code/electron-sandbox/workbench/workbench.html'
];

/** Resolves a dedicated predefined proxy port per IDE so different editors never conflict. */
function resolveDefaultProxyPort(env = {}) {
    const label = `${env.appName || ''} ${env.uriScheme || ''}`.toLowerCase();
    for (const item of IDE_PROXY_PORTS) {
        if (label.includes(item.match)) return item.port;
    }
    const detected = resolveEditorRegistry(env);
    return (detected.registry && REGISTRY_PROXY_PORTS[detected.registry]) || DEFAULT_PROXY_PORT;
}

function isLoopbackUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    return /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(rawUrl.trim());
}

const buildProxyServiceUrl = port => `http://127.0.0.1:${port}${PROXY_GALLERY_PATH}`;
const computeChecksum = text => crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('base64').replace(/=+$/, '');

function loadProxyState(context) {
    const base = { active: false, port: DEFAULT_PROXY_PORT, savedGalleryServiceUrl: undefined, savedDevGuardMarketplace: undefined, upstreamServiceUrl: null };
    try {
        const raw = context && context.globalState ? context.globalState.get(PROXY_STATE_KEY) : null;
        if (!raw || typeof raw !== 'object') return base;
        return {
            active: Boolean(raw.active),
            port: Number.isInteger(raw.port) && raw.port > 0 ? raw.port : DEFAULT_PROXY_PORT,
            savedGalleryServiceUrl: typeof raw.savedGalleryServiceUrl === 'string' ? raw.savedGalleryServiceUrl : undefined,
            savedDevGuardMarketplace: typeof raw.savedDevGuardMarketplace === 'string' ? raw.savedDevGuardMarketplace : undefined,
            upstreamServiceUrl: typeof raw.upstreamServiceUrl === 'string' && !isLoopbackUrl(raw.upstreamServiceUrl) ? raw.upstreamServiceUrl : null
        };
    } catch (_e) { return base; }
}

async function saveProxyState(context, state) {
    try { if (context && context.globalState) await context.globalState.update(PROXY_STATE_KEY, state); }
    catch (error) { console.warn('Could not save proxy state:', error); }
}

function readSetting(vscodeApi, section, key, fallback = '') {
    try {
        const val = vscodeApi.workspace.getConfiguration(section)?.get(key, fallback);
        return typeof val === 'string' ? val.trim() : fallback;
    } catch (_e) { return fallback; }
}

function resolveUpstreamMarketplace(context, vscodeApi, envOverride) {
    const state = loadProxyState(context);
    const candidates = [
        [readSetting(vscodeApi, 'devGuard', 'marketplace', ''), 'custom URL'],
        [state.savedDevGuardMarketplace, 'custom URL'],
        [readSetting(vscodeApi, 'extensions.gallery', 'serviceUrl', ''), 'extensions.gallery.serviceUrl'],
        [state.savedGalleryServiceUrl, 'extensions.gallery.serviceUrl']
    ];
    for (const [raw, method] of candidates) {
        if (typeof raw === 'string' && /^https?:\/\//i.test(raw) && !isLoopbackUrl(raw)) {
            const clean = raw.replace(/\/+$/, '');
            return { serviceUrl: clean, registry: registryFromGalleryConfig({ serviceUrl: clean }), method };
        }
    }
    return resolveEditorGalleryUrl(envOverride || (vscodeApi && vscodeApi.env) || {});
}

/** Adds `http://127.0.0.1:*` to `workbench.html` CSP when `connect-src` only allows `https:`. */
function patchWorkbenchHtmlCsp(appRoot, parsedProduct, read, write) {
    const gallery = parsedProduct.extensionsGallery;
    const checksums = parsedProduct.checksums;
    for (const relKey of WORKBENCH_HTML_CANDIDATES) {
        const htmlPath = path.join(appRoot, 'out', ...relKey.split('/'));
        let rawHtml;
        try { rawHtml = read(htmlPath, 'utf8'); } catch (_e) { continue; }
        if (typeof rawHtml !== 'string' || /connect-src[\s\S]*?;/.exec(rawHtml)?.[0]?.includes('http:')) return false;
        if (rawHtml.includes('http://127.0.0.1:*')) return false;

        const eol = rawHtml.includes('\r\n') ? '\r\n' : '\n';
        const nextHtml = rawHtml
            .replace(/(img-src[\s\S]*?https:)/, `$1${eol}\t\t\t\t\thttp://127.0.0.1:*`)
            .replace(/(connect-src[\s\S]*?https:)/, `$1${eol}\t\t\t\t\thttp://127.0.0.1:*`);
        if (nextHtml === rawHtml) return false;

        if (checksums && typeof checksums[relKey] === 'string') {
            if (!gallery._devGuardOriginalWorkbenchHtmlChecksum) {
                gallery._devGuardOriginalWorkbenchHtmlChecksum = checksums[relKey];
                gallery._devGuardWorkbenchHtmlKey = relKey;
            }
            checksums[relKey] = computeChecksum(nextHtml);
        }
        write(htmlPath, nextHtml, 'utf8');
        return true;
    }
    return false;
}

/** Restores `workbench.html` CSP and its original `product.json#checksums` entry. */
function restoreWorkbenchHtmlCsp(appRoot, parsedProduct, read, write) {
    const gallery = parsedProduct.extensionsGallery || {};
    const checksums = parsedProduct.checksums;
    let changed = false;
    for (const relKey of WORKBENCH_HTML_CANDIDATES) {
        const htmlPath = path.join(appRoot, 'out', ...relKey.split('/'));
        let rawHtml;
        try { rawHtml = read(htmlPath, 'utf8'); } catch (_e) { continue; }
        if (typeof rawHtml === 'string' && rawHtml.includes('http://127.0.0.1:*')) {
            const restored = rawHtml.replace(/((?:img-src|connect-src)[^;]*?)\r?\n[ \t]*http:\/\/127\.0\.0\.1:\*/g, '$1');
            if (restored !== rawHtml) {
                write(htmlPath, restored, 'utf8');
                if (checksums && checksums[relKey]) checksums[relKey] = gallery._devGuardOriginalWorkbenchHtmlChecksum || computeChecksum(restored);
                changed = true;
            }
        }
    }
    if (gallery._devGuardOriginalWorkbenchHtmlChecksum) {
        const key = gallery._devGuardWorkbenchHtmlKey;
        if (key && checksums) checksums[key] = gallery._devGuardOriginalWorkbenchHtmlChecksum;
        delete gallery._devGuardOriginalWorkbenchHtmlChecksum;
        delete gallery._devGuardWorkbenchHtmlKey;
        changed = true;
    }
    return changed;
}

function patchProductJsonGallery(env = {}, proxyUrl) {
    if (!env || typeof env.appRoot !== 'string' || !env.appRoot) return false;
    const read = env.readFileSync || fs.readFileSync;
    const write = env.writeFileSync || fs.writeFileSync;
    try {
        const productPath = path.join(env.appRoot, 'product.json');
        const parsed = JSON.parse(read(productPath, 'utf8'));
        const gallery = parsed && parsed.extensionsGallery;
        if (!gallery || typeof gallery !== 'object') return false;

        const proxyLatest = `${proxyUrl}/vscode/{publisher}/{name}/latest`;
        let changed = patchWorkbenchHtmlCsp(env.appRoot, parsed, read, write);
        if (gallery.serviceUrl !== proxyUrl || (gallery.extensionUrlTemplate && gallery.extensionUrlTemplate !== proxyLatest)) {
            if (gallery.serviceUrl && !isLoopbackUrl(gallery.serviceUrl)) gallery._devGuardOriginalServiceUrl = gallery.serviceUrl;
            if (gallery.extensionUrlTemplate && !isLoopbackUrl(gallery.extensionUrlTemplate)) gallery._devGuardOriginalExtensionUrlTemplate = gallery.extensionUrlTemplate;
            gallery.serviceUrl = proxyUrl;
            if (gallery.extensionUrlTemplate) gallery.extensionUrlTemplate = proxyLatest;
            changed = true;
        }
        if (changed) write(productPath, `${JSON.stringify(parsed, null, '\t')}\n`, 'utf8');
        return changed;
    } catch (_e) { return false; }
}

function restoreProductJsonGallery(env = {}, fallbackServiceUrl) {
    if (!env || typeof env.appRoot !== 'string' || !env.appRoot) return false;
    const read = env.readFileSync || fs.readFileSync;
    const write = env.writeFileSync || fs.writeFileSync;
    try {
        const productPath = path.join(env.appRoot, 'product.json');
        const parsed = JSON.parse(read(productPath, 'utf8'));
        const gallery = parsed && parsed.extensionsGallery;
        if (!gallery || typeof gallery !== 'object') return false;

        let changed = restoreWorkbenchHtmlCsp(env.appRoot, parsed, read, write);
        if (isLoopbackUrl(gallery.serviceUrl) || gallery._devGuardOriginalServiceUrl) {
            const orig = gallery._devGuardOriginalServiceUrl || fallbackServiceUrl;
            if (orig && !isLoopbackUrl(orig)) { gallery.serviceUrl = orig; changed = true; }
            delete gallery._devGuardOriginalServiceUrl;
        }
        if (gallery._devGuardOriginalExtensionUrlTemplate) {
            gallery.extensionUrlTemplate = gallery._devGuardOriginalExtensionUrlTemplate;
            delete gallery._devGuardOriginalExtensionUrlTemplate;
            changed = true;
        }
        if (changed) write(productPath, `${JSON.stringify(parsed, null, '\t')}\n`, 'utf8');
        return changed;
    } catch (_e) { return false; }
}

async function applyProxyMarketplaceConfig(context, vscodeApi, port, upstreamServiceUrl) {
    const prev = loadProxyState(context);
    const currentGallery = readSetting(vscodeApi, 'extensions.gallery', 'serviceUrl', '');
    const currentMp = readSetting(vscodeApi, 'devGuard', 'marketplace', '');
    const proxyUrl = buildProxyServiceUrl(port);
    const nextState = {
        active: true, port, upstreamServiceUrl,
        savedGalleryServiceUrl: !isLoopbackUrl(currentGallery) ? currentGallery : (prev.savedGalleryServiceUrl ?? ''),
        savedDevGuardMarketplace: !isLoopbackUrl(currentMp) && currentMp !== 'custom' ? currentMp : (prev.savedDevGuardMarketplace ?? '')
    };
    await saveProxyState(context, nextState);
    writeUninstallRestoreManifest(context, vscodeApi, nextState);

    const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
    let productJsonChanged = false;
    let usedProductJson = false;
    let gallerySettingChanged = false;
    if (currentGallery !== proxyUrl) {
        try {
            await vscodeApi.workspace.getConfiguration('extensions.gallery').update('serviceUrl', proxyUrl, target);
            gallerySettingChanged = true;
        } catch (_e) {
            usedProductJson = true;
            productJsonChanged = patchProductJsonGallery(vscodeApi && vscodeApi.env, proxyUrl);
        }
    }
    if (currentMp !== proxyUrl) {
        try { await vscodeApi.workspace.getConfiguration('devGuard').update('marketplace', proxyUrl, target); } catch (_e) { /* ignore */ }
    }
    const restartRequired = Boolean(gallerySettingChanged || productJsonChanged);
    return { ...nextState, productJsonChanged, usedProductJson, restartRequired };
}

async function restoreProxyMarketplaceConfig(context, vscodeApi) {
    const prev = loadProxyState(context);
    const target = vscodeApi.ConfigurationTarget ? vscodeApi.ConfigurationTarget.Global : true;
    let gallerySettingRestored = false;
    if (isLoopbackUrl(readSetting(vscodeApi, 'extensions.gallery', 'serviceUrl', ''))) {
        try {
            await vscodeApi.workspace.getConfiguration('extensions.gallery').update('serviceUrl', prev.savedGalleryServiceUrl || undefined, target);
            gallerySettingRestored = true;
        } catch (_e) { /* ignore */ }
    }
    const productJsonRestored = restoreProductJsonGallery(vscodeApi && vscodeApi.env, prev.upstreamServiceUrl);
    if (isLoopbackUrl(readSetting(vscodeApi, 'devGuard', 'marketplace', ''))) {
        try { await vscodeApi.workspace.getConfiguration('devGuard').update('marketplace', prev.savedDevGuardMarketplace || '', target); } catch (_e) { /* ignore */ }
    }
    const restartRequired = Boolean(gallerySettingRestored || productJsonRestored);
    const nextState = { ...prev, active: false };
    await saveProxyState(context, nextState);
    return { ...nextState, productJsonRestored, restartRequired };
}

module.exports = {
    PROXY_STATE_KEY, DEFAULT_PROXY_PORT, IDE_PROXY_PORTS, REGISTRY_PROXY_PORTS, PROXY_GALLERY_PATH,
    resolveDefaultProxyPort, isLoopbackUrl, buildProxyServiceUrl, loadProxyState, saveProxyState,
    patchProductJsonGallery, restoreProductJsonGallery, resolveUpstreamMarketplace,
    applyProxyMarketplaceConfig, restoreProxyMarketplaceConfig
};
