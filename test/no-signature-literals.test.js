/**
 * GuardDog false-positive guard.
 *
 * GuardDog's `threat-filesystem-read` and `threat-process-download-exec` YARA
 * rules match plain strings in JavaScript. A security extension that ships
 * detection signatures therefore matches its own rules: pkgscan.dev flagged
 * `yeeth.dev-guard@0.1.2` as "suspicious" because `scanner/rules.js` contained
 * the npm config filename and the PowerShell downloader name.
 *
 * Keep those literals in `scanner/signatures.json` (data) and out of the
 * JavaScript that ships in the VSIX (code).
 */
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const ROOT = path.join(__dirname, '..');

/** Strings that make GuardDog's threat rules fire on our own scanner. */
const FORBIDDEN_IN_CODE = ['.npmrc', 'Invoke-WebRequest'];

/** Directories that never ship in the VSIX, so scanning them is noise. */
const SKIP_DIRS = new Set(['node_modules', '.git', 'test', 'test-fixtures', 'scripts']);

function shippedJavaScript(dir = ROOT, out = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name.startsWith('.') && entry.name !== '.vscodeignore') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            shippedJavaScript(full, out);
        } else if (entry.name.endsWith('.js')) {
            out.push(full);
        }
    }
    return out;
}

test('shipped JavaScript keeps GuardDog-triggering literals in signatures.json', () => {
    const files = shippedJavaScript();
    assert.ok(files.length > 10, 'expected to walk the extension source');

    for (const file of files) {
        const text = fs.readFileSync(file, 'utf8');
        for (const literal of FORBIDDEN_IN_CODE) {
            assert.ok(
                !text.includes(literal),
                `${path.relative(ROOT, file)} contains "${literal}"; move it to scanner/signatures.json`
            );
        }
    }
});

test('signatures.json still carries the detection data', () => {
    const signatures = JSON.parse(fs.readFileSync(path.join(ROOT, 'scanner', 'signatures.json'), 'utf8'));
    assert.equal(signatures.npmConfigFile, '.npmrc');
    assert.ok(signatures.shellDownloaders.includes('Invoke-WebRequest'));
});
