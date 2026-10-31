<div align="center">

<table style="border: none; margin: 0 auto; padding: 0; border-collapse: collapse;">
<tr>
<td align="center" style="vertical-align: middle; padding: 10px; border: none; width: 220px;">
  <img src="icons/icon128.png" alt="DevGuard Logo" width="180"/>
</td>
<td align="left" style="vertical-align: middle; padding: 10px 0 10px 30px; border: none;">
  <pre style="font-family: 'Courier New', monospace; font-size: 15px; color: #22d3ee; margin: 0; padding: 0; text-shadow: 0 0 10px #22d3ee, 0 0 20px rgba(34,211,238,0.5); line-height: 1.2; display: block;">
██████╗ ███████╗██╗   ██╗        ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██║   ██║       ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║  ██║█████╗  ██║   ██║█████╗ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║  ██║██╔══╝  ╚██╗ ██╔╝╚════╝ ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██████╔╝███████╗ ╚████╔╝        ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═════╝ ╚══════╝  ╚═══╝          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
  </pre>
</td>
</tr>
</table>

[![pkgscan.dev](https://www.pkgscan.dev/api/badge/vscode-extension/yeeth/dev-guard%400.1.0?repository_url=https%3A%2F%2Fopen-vsx.org)](https://www.pkgscan.dev/pkg/vscode-extension/yeeth/dev-guard%400.1.0?repository_url=https%3A%2F%2Fopen-vsx.org)

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

## 🔐 How it works

* **Live advisories.** Every scan checks your extensions against the public [pkgscan.dev](https://www.pkgscan.dev) malicious-extension feed for VS Code, Cursor, and Open VSX, plus the community [blocklist](/malicious.json). The feed refreshes every 5 minutes, and installing an extension triggers an immediate scan.
* **Removal.** Flagged extensions are uninstalled automatically by default (`devGuard.removalMode`: `auto` · `manual` · `warn`) and removed again if reinstalled. Add an ID to `devGuard.allowlist` to opt one out. Every removal links to a [cleanup guide](https://yeethsecurity.com/guides/vscode-extension-malware/#remove) for what to do next.
* **Side pane.** The shield in the Activity Bar shows your current verdict, lets you run a scan and change settings, and keeps a scan log, removed list, audit log, and a hashed inventory of what was checked. Everything is stored locally.
* **Remote windows.** DevGuard sees the extensions in its own window; for SSH, WSL, or Dev Containers, install it in the remote as well.

---

## Telemetry

DevGuard sends pseudonymous usage stats to pkgscan.dev so we can tell whether it is working in the field. Turn it off with `devGuard.telemetry.enabled`, or by disabling your editor's telemetry.

* **Sent:** scan outcomes, which extensions were flagged or removed (ID, version, severity), buttons clicked, extension and editor versions, OS, and a random install ID.
* **Never sent:** file paths, extension display names, advisory text, or machine identifiers.

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
