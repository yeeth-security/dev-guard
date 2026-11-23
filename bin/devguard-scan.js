#!/usr/bin/env node
'use strict';

/**
 * Headless entry point for the workspace rules (`bin/devguard-scan.js`).
 *
 * Why this file exists:
 *   `scanner/workspace.js` is a pure module with no `vscode` import, so the
 *   checks that protect the editor can also run in CI or a git hook.
 *   This CLI only calls the existing scanner. It adds no detection logic.
 *
 * Usage: devguard-scan <path...> [--json]
 * Exit codes: 0 clean, 1 any critical/high finding, 2 usage error.
 */

const fs = require('fs');
const path = require('path');
const { scanWorkspaceFolder } = require('../scanner/workspace');

const USAGE = 'Usage: devguard-scan <path...> [--json]';
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** Prints a usage error and exits 2 (never returns). */
function usageError(message) {
    process.stderr.write(`devguard-scan: ${message}\n${USAGE}\n`);
    process.exit(2);
}

function parseArgs(argv) {
    const paths = [];
    let json = false;
    for (const arg of argv) {
        if (arg === '--json') {
            json = true;
        } else if (arg === '--help' || arg === '-h') {
            process.stdout.write(`${USAGE}\n`);
            process.exit(0);
        } else if (arg.startsWith('-')) {
            usageError(`unknown option ${arg}`);
        } else {
            paths.push(arg);
        }
    }
    if (paths.length === 0) usageError('no paths given');
    return { paths, json };
}

function toPosix(value) {
    return String(value).split(path.sep).join('/');
}

/** Runs `scanWorkspaceFolder` on every path and flattens its matches into findings. */
function scanPaths(paths) {
    const findings = [];
    for (const input of paths) {
        const root = path.resolve(input);
        let stat;
        try {
            stat = fs.statSync(root);
        } catch (_err) {
            usageError(`no such path: ${input}`);
        }
        if (!stat.isDirectory()) usageError(`not a directory: ${input}`);

        for (const result of scanWorkspaceFolder(root)) {
            const file = toPosix(path.relative(root, result.filePath)) || result.displayPath || result.fileName;
            for (const match of result.matches || []) {
                findings.push({
                    rule: match.rule,
                    technique: match.technique || null,
                    severity: match.severity,
                    file,
                    detail: match.detail
                });
            }
        }
    }
    return findings;
}

function summarize(findings) {
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
        const key = String(finding.severity || '').toLowerCase();
        if (key in summary) summary[key] += 1;
    }
    return summary;
}

function main() {
    const { paths, json } = parseArgs(process.argv.slice(2));
    const findings = scanPaths(paths).sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
        || a.file.localeCompare(b.file));
    const summary = summarize(findings);

    if (json) {
        process.stdout.write(`${JSON.stringify({ findings, summary }, null, 2)}\n`);
    } else {
        const lines = findings.map(f => `${f.severity} ${f.rule} ${f.file} ${f.detail}`);
        process.stdout.write(`${lines.length > 0 ? `${lines.join('\n')}\n` : ''}`);
        process.stdout.write(`summary: ${SEVERITIES.map(k => `${summary[k]} ${k}`).join(', ')}\n`);
    }

    process.exit(summary.critical + summary.high > 0 ? 1 : 0);
}

main();
