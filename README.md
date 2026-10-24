<div align="center">

<table style="border: none; margin: 0 auto; padding: 0; border-collapse: collapse;">
<tr>
<td align="center" style="vertical-align: middle; padding: 10px; border: none; width: 220px;">
  <img src="icons/icon128.png" alt="DevGuard Logo" width="180"/>
</td>
<td align="left" style="vertical-align: middle; padding: 10px 0 10px 30px; border: none;">
  <pre style="font-family: 'Courier New', monospace; font-size: 15px; color: #22d3ee; margin: 0; padding: 0; text-shadow: 0 0 10px #22d3ee, 0 0 20px rgba(34,211,238,0.5); line-height: 1.2; display: block;">
██████╗ ███████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██║   ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║  ██║█████╗  ██║   ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║  ██║██╔══╝  ╚██╗ ██╔╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██████╔╝███████╗ ╚████╔╝ ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═════╝ ╚══════╝  ╚═══╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
  </pre>
</td>
</tr>
</table>

[![pkgscan.dev](https://www.pkgscan.dev/api/badge/vscode-extension/yeeth/dev-guard%400.0.6?repository_url=https%3A%2F%2Fopen-vsx.org)](https://www.pkgscan.dev/pkg/vscode-extension/yeeth/dev-guard%400.0.6?repository_url=https%3A%2F%2Fopen-vsx.org)

---

### *Protecting Developers from Malicious Extensions*

<p>
  <a href="https://github.com/yeeth-security/dev-guard/stargazers"><img src="https://img.shields.io/github/stars/yeeth-security/dev-guard?color=22d3ee&style=for-the-badge&logo=star&logoColor=white&labelColor=0f172a" /></a>
  <img src="https://img.shields.io/badge/🖥️IDE-Security-0ea5e9?style=for-the-badge&logo=visualstudiocode&logoColor=white&labelColor=0f172a">
  <img src="https://img.shields.io/badge/License-AGPL3.0-10b981?style=for-the-badge&logo=open-source-initiative&logoColor=white&labelColor=0f172a">
</p>

<p>
  <a href="https://github.com/yeeth-security/dev-guard/issues"><img src="https://img.shields.io/badge/🐛_Report_Issue-E11D48?style=for-the-badge&logo=github&logoColor=white&labelColor=0f172a"></a>
</p>

</div>

---

## 🚀 Quick Start

✅ Download the latest version of dev-guard [here](https://open-vsx.org/extension/yeeth/dev-guard).
* DevGuard scans your extensions and alerts you instantly on anything malicious

---

## ✨ Features

<table align="center" width="100%" style="border: none; table-layout: fixed;">
<tr>
<td align="center" width="33%" style="padding: 15px;">
<h3>🔍 Auto Scan</h3>
<p>Runs automatically on startup, no setup required.</p>
</td>
<td align="center" width="33%" style="padding: 15px;">
<h3>⚡ Real-Time Monitor</h3>
<p>Detects extension changes the moment they happen.</p>
</td>
<td align="center" width="33%" style="padding: 15px;">
<h3>🛑 One-Click Uninstall</h3>
<p>Neutralize malicious extensions instantly.</p>
</td>
</tr>
<tr>
<td align="center" width="33%" style="padding: 15px;">
<h3>📊 Live Advisories</h3>
<p>Pulls the latest malicious-package advisories from pkgscan.dev.</p>
</td>
<td align="center" width="33%" style="padding: 15px;">
<h3>🛰️ Verdict Checks</h3>
<p>Matches installed extensions and versions against multi-engine scan verdicts.</p>
</td>
<td align="center" width="33%" style="padding: 15px;">
<h3>🧩 IDE Native</h3>
<p>Built on the standard VS Code extension API, so it works across Cursor, Windsurf, VSCodium, and other AI IDEs.</p>
</td>
</tr>
</table>

---

## 🔐 Security

* Starts from the community [GitHub blocklist](https://github.com/yeeth-security/dev-guard/blob/main/malicious.json) on every audit
* Adds confirmed malicious VS Code / Open VSX extensions from the public [pkgscan.dev advisories API](https://www.pkgscan.dev/api/advisories?kind=malicious) on top
* First sync fetches all advisory pages; later refreshes are **incremental** and stop at the previous sync cursor, so normally only one page is fetched
* Matches by extension ID and, when the advisory names specific versions, by installed version
* Caches the GitHub blocklist for 10 minutes and advisories for one hour; falls back to the previous cache and then to the bundled [`malicious.json`](/malicious.json) when a source is unreachable
* A full pkgscan.dev re-sync runs once a day to pick up removed advisories

---

## Telemetry

dev-guard sends pseudonymous usage stats to pkgscan.dev so we can see whether the extension is working in the field. It is **enabled by default** and can be turned off at any time:

- Setting: `devGuard.telemetry.enabled`
- Or disable your editor's telemetry globally (VS Code, Cursor, Windsurf, …) — dev-guard respects it

What is sent:

* Activation, audit duration (bucketed), installed-extension count (bucketed)
* Findings count and which source answered (`github`, `github+pkgscan`, `bundled`)
* **Which extensions were blocked** — one `malicious_found` event per detected extension with its ID, installed version, severity, and whether it came from the blocklist or a pkgscan.dev advisory
* Buttons clicked (`Uninstall`, `View Report`, including the extension ID) and error/fallback signals
* Extension version, editor name/version, OS, and a random install ID

What is **never** sent: file paths, extension display names, advisory text, or machine identifiers. Events are validated and forwarded to our GA4 property server-side; the GA4 API secret never ships in the extension.

---

## 📦 Releasing

Releases are generated by the [`release`](/.github/workflows/release.yml) workflow:

1. Bump `version` in [`package.json`](/package.json) and merge to `main`
2. Run **Actions → release → Run workflow** (or `gh workflow run release.yml`)
3. The job validates the sources, packages a VSIX, tags `v<version>`, creates a GitHub Release with auto-generated notes and a `.sha256` checksum, then dispatches the Open VSX publish workflow

It refuses to run if the tag or release already exists, so a release always maps to a version bump. Uncheck **publish** to create the release without pushing to Open VSX, or check **prerelease** to mark it as a pre-release.

Publishing uses Open VSX [trusted publishing](https://github.com/eclipse-openvsx/openvsx/wiki/Trusted-Publishing): the [`publish`](/.github/workflows/publish.yml) workflow requests a GitHub OIDC ID token and the registry exchanges it for a short-lived, single-extension token. **No `OVSX_PAT` secret is stored.** The one-time registration lives on [Open VSX → Settings → Trusted Publishers](https://open-vsx.org/user-settings/trusted-publishers) for the `yeeth` namespace:

| Field | Value |
|---|---|
| Organization or user name | `yeeth-security` |
| Repository name | `dev-guard` |
| Workflow filename | `publish.yml` |
| Environment name | `publish` |

The environment pin is what restricts publishing to runs that passed the `publish` environment's protection rules (required reviewers), so keep the `environment: publish` line in the workflow and the registration in sync.

---

## 🤝 Contribute

Spotted a shady extension? 🕵️‍♂️

* Add it to [`malicious.json`](/malicious.json)
* Submit a PR here: [dev-guard](https://github.com/yeeth-security/dev-guard)

---

## 🛡️ Team

* [unsafe_call](https://x.com/unsafe_call)
* [bkojusner](https://x.com/v0ldemort5545)
* [alejandro-n-rivera](https://github.com/alejandro-n-rivera)

---

<div align="center">

### ⭐ Star DevGuard if you believe every dev deserves a secure editor!

</div>
