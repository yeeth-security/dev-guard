/**
 * Extension Security Auditor for Cursor
 * 
 * @fileoverview A security extension that scans and monitors installed extensions
 *              for known malicious patterns and provides real-time security alerts.
 * 
 * @author v0ldemort5545, unsafe_call
 * @version 0.0.1
 * @since 2025-08-19
 * 
 * @description This extension provides comprehensive security auditing for Cursor extensions:
 *             - Automatically scans all installed extensions on startup
 *             - Monitors for extension changes and re-runs security audits on extension changes
 *             - Provides uninstall options for malicious extensions
 * 
 * @usage The extension activates automatically on startup and can be manually triggered
 *        via the command palette: "Extension Security Auditor: Check Installed Extensions"
 * 
 */

// The module 'vscode' contains the Cursor extensibility API (Cursor is built on VS Code)
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

/**
 * This function is called when your extension is activated.
 * The 'activationEvents' in package.json determine when this runs.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Extension Security Auditor is now active in Cursor!');

    // Initial check on startup
    checkAndReportMaliciousExtensions(context);

    // Subscribe to the onDidChange event
    context.subscriptions.push(vscode.extensions.onDidChange(() => {
        console.log('Extension list changed. Re-running security audit...');
        checkAndReportMaliciousExtensions(context);
    }));

    let disposable = vscode.commands.registerCommand('extension-security-auditor.checkExtensions', () => {
        vscode.window.showInformationMessage('Starting security audit of installed extensions...');
        checkAndReportMaliciousExtensions(context);
    });

    context.subscriptions.push(disposable);
}

/**
 * Reads the list of known malicious extension IDs from a local JSON file.
 * @param {vscode.ExtensionContext} context
 * @returns {string[]} An array of malicious extension IDs.
 */
function getMaliciousExtensionsList(context) {
    const maliciousFilePath = path.join(context.extensionPath, 'malicious.json');
    try {
        const fileContent = fs.readFileSync(maliciousFilePath, 'utf8');
        return JSON.parse(fileContent);
    } catch (error) {
        console.error("Could not read or parse malicious.json file:", error);
        vscode.window.showErrorMessage("Failed to load malicious extensions list. Check the extension's files.");
        return [];
    }
}

/**
 * Checks all installed extensions against a malicious list and alerts the user.
 * @param {vscode.ExtensionContext} context
 */
function checkAndReportMaliciousExtensions(context) {
    const allExtensions = vscode.extensions.all;
    console.log(allExtensions);
    const maliciousList = getMaliciousExtensionsList(context);

    // If the malicious list is empty, there's nothing to do.
    if (maliciousList.length === 0) {
        return;
    }

    const foundMaliciousExtensions = [];
    let processedCount = 0; // Track how many extensions have been processed (uninstalled or dismissed)
    let uninstalledCount = 0; // Track how many extensions have been uninstalled

    // Loop through all installed extensions.
    for (const extension of allExtensions) {
        // Check if the extension's ID is in our malicious list.
        if (maliciousList.includes(extension.id)) {
            foundMaliciousExtensions.push(extension);
        }
    }

    // Report findings to the user.
    if (foundMaliciousExtensions.length > 0) {
        // Create an output channel to show detailed information.
        const outputChannel = vscode.window.createOutputChannel("Extension Security Auditor");
        outputChannel.show(true);
        outputChannel.appendLine("--- SECURITY AUDIT REPORT ---");
        outputChannel.appendLine(`Scan completed on ${new Date().toLocaleString()}`);
        outputChannel.appendLine("--- WARNING: Malicious Extensions Found ---");

        foundMaliciousExtensions.forEach(extension => {
            const extensionName = extension.packageJSON.displayName || extension.id;
            outputChannel.appendLine(`- Name: ${extensionName}`);
            outputChannel.appendLine(`  ID: ${extension.id}`);
            outputChannel.appendLine("  Reason: Found on the known malicious list. This extension may pose a security risk.");
            outputChannel.appendLine("-------------------");
            
            // Show a warning message with an "Uninstall" button for each malicious extension.
            vscode.window.showWarningMessage(
                `Malicious extension found: '${extensionName}'`,
                "Uninstall"
            ).then(selection => {
                // Increment the processed counter regardless of user choice
                processedCount++;
                
                if (selection === "Uninstall") {
                    // This command triggers the built-in Cursor uninstaller.
                    // It requires user confirmation.
                    vscode.commands.executeCommand('workbench.extensions.uninstallExtension', extension.id);
                    uninstalledCount++;
                }
                
                // Check if this was the last extension to be processed (uninstalled or dismissed)
                if (processedCount === foundMaliciousExtensions.length && uninstalledCount > 0) {
                    // Show restart prompt after all extensions have been processed
                    setTimeout(() => {
                        vscode.window.showInformationMessage(
                            'Security audit completed. Cursor needs to restart to complete uninstallations.',
                            'Restart Cursor'
                        ).then(restartSelection => {
                            if (restartSelection === 'Restart Cursor') {
                                // Execute the restart command
                                vscode.commands.executeCommand('workbench.action.reloadWindow');
                            }
                        });
                    }, 1000); // Small delay to ensure all commands have been processed
                }
            });
        });

        outputChannel.appendLine("--- IMPORTANT ---");
        outputChannel.appendLine("The detected extensions were found on a local malicious list. Please verify the extensions and consider uninstalling them immediately.");
        outputChannel.appendLine("-------------------");

    } else {
        vscode.window.showInformationMessage('No known malicious extensions found. Your Cursor environment is looking good!');
    }
}

/**
 * This function is called when your extension is deactivated.
 */
function deactivate() {}

// Module exports
module.exports = {
    activate,
    deactivate
}