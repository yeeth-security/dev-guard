/**
 * The pkgscan.dev badge in README.md must be versionless.
 *
 * A pinned badge (`.../yeeth/dev-guard%400.1.2`) is baked into the VSIX when the
 * release is packaged from a tag. The badge-sync commit lands on main after that
 * tag, so the published listing keeps rendering the previous release's verdict —
 * a "clean" badge for a version pkgscan considers suspicious. The versionless URL
 * resolves to the latest scanned version at render time and cannot go stale.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const README = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
const EXTENSION_PATH = 'vscode-extension/yeeth/dev-guard';

test('README.md carries a pkgscan.dev badge', () => {
    assert.ok(README.includes(`/api/badge/${EXTENSION_PATH}`), 'README.md has no pkgscan.dev badge');
});

test('the pkgscan.dev badge and link are not pinned to a version', () => {
    const urls = README.match(new RegExp(`https://www\\.pkgscan\\.dev/[^\\s)"']*${EXTENSION_PATH}[^\\s)"']*`, 'g')) || [];
    assert.ok(urls.length > 0, 'no pkgscan.dev URL for this extension in README.md');
    for (const url of urls) {
        assert.ok(
            !url.includes('%40') && !new RegExp(`${EXTENSION_PATH}@\\d`).test(url),
            `pkgscan.dev URL is pinned to a version: ${url}`
        );
    }
});
