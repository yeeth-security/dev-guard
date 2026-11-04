/**
 * VS Code extension post-uninstall hook (`"vscode:uninstall"` in `package.json`).
 *
 * Why this file exists:
 *   VS Code executes `"vscode:uninstall": "node scripts/uninstall.js"` in a
 *   standalone Node child process when cleaning up an uninstalled extension.
 *   This script reads the persisted restore manifest (`uninstall-restore.json`)
 *   for the editor being uninstalled from (`__dirname`) and reverts
 *   `extensions.gallery.serviceUrl`, `devGuard.marketplace`, and
 *   `product.json#extensionsGallery` back to the user's previous marketplace
 *   configuration so the editor's marketplace continues working after uninstall.
 */

const { restoreProductJsonGallery } = require('../proxy/config');
const { runUninstallRestore } = require('../proxy/uninstall');

try {
    runUninstallRestore({ scriptDir: __dirname, restoreProductJsonGallery });
} catch (error) {
    console.warn('dev-guard uninstall hook warning:', error);
}
