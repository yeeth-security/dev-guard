// This is the main file for the VS Code extension.

// The module 'vscode' contains the VS Code extensibility API
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

/**
 * This function is called when your extension is activated.
 * The 'activationEvents' in package.json determine when this runs.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Extension Security Auditor is now active!');

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
                if (selection === "Uninstall") {
                    // This command triggers the built-in VS Code uninstaller.
                    // It requires user confirmation.
                    vscode.commands.executeCommand('workbench.extensions.uninstallExtension', extension.id);
                }
            });
        });

        outputChannel.appendLine("--- IMPORTANT ---");
        outputChannel.appendLine("The detected extensions were found on a local malicious list. Please verify the extensions and consider uninstalling them immediately.");
        outputChannel.appendLine("-------------------");

    } else {
        vscode.window.showInformationMessage('No known malicious extensions found. Your environment is looking good!');
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