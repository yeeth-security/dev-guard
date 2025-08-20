# dev-guard
Protects developers from malicious Cursor extensions

## How to use
1. Clone repo
1. CD into repo and run `npm install`
1. Open the repo in Cursor and open `extension.js`
1. Open the "Run and Debug" tab and click on `Run and Debug`
    - Make sure you select to run in the extension testing environment
1. In the new Cursor window you can hit `Ctrl + Shift + P` to "Show and Run Commands >"
1. In the search box type "Extension Security Auditor: Check Installed Extensions"
1. Click on the result in the search box to run the plugin and you'll see announcements at the bottom right

## Features
- Automatically scans for malicious extensions on startup
- Monitors for extension changes and re-runs security audit
- Compares installed extensions against a known malicious list
- Provides detailed security reports in output channels
- Offers one-click uninstall for detected malicious extensions
- Works seamlessly with Cursor's extension system

## Security
This extension maintains a local list of known malicious extension IDs in `malicious.json`. The list is regularly updated to include extensions that have been identified as security risks.

# TODO
- [ ] Make sure it refreshes itself each time an extension is uninstalled
- [ ] Get IDs to populate malicious Cursor plugins JSON file
- [ ] Make plugin just run after each change in the plugins directory
- [ ] Add automatic updates for the malicious extensions database
- [ ] Implement real-time scanning during extension installation