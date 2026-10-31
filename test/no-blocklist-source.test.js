// Regression guard for ENG-25: pkgscan.dev is the only advisory source.
//
// DevGuard 0.1.1 removed the GitHub blocklist (malicious.json) from the audit.
// The file stays at its public URL for older clients, but this package must
// never read it again. Its key was `publisher.name`, which cannot separate a
// malicious impersonation from the real product under the same name, so
// matching on it blocked legitimate extensions.
//
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const mainSource = fs.readFileSync(path.join(ROOT, 'extension.js'), 'utf8');

const CODE = mainSource
    .split('\n')
    .map(line => line.replace(/\/\/.*$/, ''))
    .filter(line => !line.trim().startsWith('*') && !line.trim().startsWith('/*'))
    .join('\n');

test('extension.js does not fetch the GitHub blocklist', () => {
    assert.doesNotMatch(CODE, /GITHUB_BLOCKLIST/);
    assert.doesNotMatch(CODE, /raw\.githubusercontent\.com/);
});

test('extension.js does not read the bundled blocklist file', () => {
    assert.doesNotMatch(CODE, /malicious\.json/);
    assert.doesNotMatch(CODE, /loadBundledBlocklistIds/);
});

test('extension.js does not convert blocklist ids into advisories', () => {
    assert.doesNotMatch(CODE, /blocklistToEntries/);
    assert.doesNotMatch(CODE, /getGithubBlocklist/);
    assert.doesNotMatch(CODE, /blocklist:/);
});

test('classifySource reports only pkgscan or none', () => {
    assert.match(CODE, /function classifySource\(source\) \{/);
    assert.doesNotMatch(CODE, /'github\+pkgscan'/);
    assert.doesNotMatch(CODE, /'bundled'/);
});

test('a failed pkgscan fetch yields no advisory entries', () => {
    const failure = CODE.match(/return \{ entries: \[\], source: 'none'/);
    assert.ok(failure, 'the advisory failure path must return an empty entry list, never a local list');
});

test('the retired blocklist file is not packaged', () => {
    const ignore = fs.readFileSync(path.join(ROOT, '.vscodeignore'), 'utf8');
    const lines = ignore.split('\n').map(line => line.trim());
    assert.ok(lines.includes('malicious.json'), 'malicious.json must stay out of the VSIX');
});
