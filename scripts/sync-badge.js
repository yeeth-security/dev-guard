/**
 * Keeps the pkgscan.dev badge in README.md pointed at the version in package.json.
 *
 * pkgscan.dev only serves a badge for a version it has scanned, so the version
 * is part of the URL and has to be bumped by hand on every release. This script
 * makes that mechanical step scriptable (see .github/workflows/badge.yml).
 *
 * @usage node scripts/sync-badge.js            # rewrite README.md in place
 *        node scripts/sync-badge.js --check    # exit 1 when README.md is stale
 *        node scripts/sync-badge.js --badge-url # print the badge URL, do not write
 *        node scripts/sync-badge.js --version 1.2.3  # override the package.json version
 */

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
const PACKAGE_JSON = path.join(REPO_ROOT, 'package.json');
const README = path.join(REPO_ROOT, 'README.md');

/**
 * @param {string} value
 * @returns {string}
 */
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Builds the pkgscan.dev identifier for the extension, e.g. `yeeth/dev-guard%40`.
 * @param {{ publisher: string, name: string }} pkg
 * @returns {string}
 */
function extensionPath(pkg) {
    return `${encodeURIComponent(pkg.publisher)}/${encodeURIComponent(pkg.name)}`;
}

/**
 * @param {{ publisher: string, name: string }} pkg
 * @param {string} version
 * @returns {string}
 */
function badgeUrl(pkg, version) {
    const repository = encodeURIComponent('https://open-vsx.org');
    return `https://www.pkgscan.dev/api/badge/vscode-extension/${extensionPath(pkg)}%40${version}?repository_url=${repository}`;
}

/**
 * Rewrites every pkgscan.dev URL for this extension to the given version.
 * @param {string} content
 * @param {{ publisher: string, name: string }} pkg
 * @param {string} version
 * @returns {string}
 */
function applyVersion(content, pkg, version) {
    const pattern = new RegExp(`${escapeRegExp(extensionPath(pkg))}%40[^?)\\s]+`, 'g');
    return content.replace(pattern, `${extensionPath(pkg)}%40${version}`);
}

function main() {
    const args = process.argv.slice(2);
    const check = args.includes('--check');
    const printUrl = args.includes('--badge-url');
    const versionFlag = args.indexOf('--version');
    const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8'));
    const version = versionFlag === -1 ? pkg.version : args[versionFlag + 1];

    if (!version) {
        console.error('No version found: pass --version or set "version" in package.json');
        process.exit(2);
    }

    if (printUrl) {
        console.log(badgeUrl(pkg, version));
        return;
    }

    const current = fs.readFileSync(README, 'utf8');
    const hasBadge = new RegExp(`${escapeRegExp(extensionPath(pkg))}%40`).test(current);
    if (!hasBadge) {
        console.error(`README.md has no pkgscan.dev badge for ${extensionPath(pkg)}; add one first.`);
        process.exit(2);
    }

    const updated = applyVersion(current, pkg, version);

    if (current === updated) {
        console.log(`README.md badge already points at v${version}`);
        return;
    }

    if (check) {
        console.error(`README.md badge does not point at v${version}`);
        process.exit(1);
    }

    fs.writeFileSync(README, updated);
    console.log(`README.md badge updated to v${version}`);
}

main();
