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
    checkAndReportMaliciousExtensions(context).catch(error => {
        console.error('Error during initial security audit:', error);
        vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
    });

    // Subscribe to the onDidChange event
    context.subscriptions.push(vscode.extensions.onDidChange(() => {
        console.log('Extension list changed. Re-running security audit...');
        checkAndReportMaliciousExtensions(context).catch(error => {
            console.error('Error during security audit after extension change:', error);
            vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
        });
    }));

    let disposable = vscode.commands.registerCommand('extension-security-auditor.checkExtensions', () => {
        vscode.window.showInformationMessage('Starting security audit of installed extensions...');
        checkAndReportMaliciousExtensions(context).catch(error => {
            console.error('Error during manual security audit:', error);
            vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
        });
    });

    context.subscriptions.push(disposable);
}

/**
 * Fetches the latest malicious extensions list from GitHub
 * @returns {Promise<string[]>} Array of malicious extension IDs
 */
async function fetchLatestMaliciousList() {
    try {
        // Correct raw GitHub URL to the JSON file on the main branch
        const url = 'https://raw.githubusercontent.com/janbro/openvsx-registry-guard/refs/heads/main/malicious.json';
        
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch malicious list: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        if (!Array.isArray(data)) {
            throw new Error('Unexpected format: malicious.json is not an array');
        }

        return data;
    } catch (error) {
        console.error('Unexpected error fetching from GitHub:', error);
        throw error;
    }
}

/**
 * Updates the local malicious.json file with the latest data from GitHub
 * @param {vscode.ExtensionContext} context - Extension context
 * @param {string[]} maliciousList - Array of malicious extension IDs
 */
function updateLocalMaliciousFile(context, maliciousList) {
    try {
        const maliciousFilePath = path.join(context.extensionPath, 'malicious.json');
        const content = JSON.stringify(maliciousList, null, 2);
        fs.writeFileSync(maliciousFilePath, content, 'utf8');
        console.log('Successfully updated local malicious.json file');
    } catch (error) {
        console.error('Error updating local malicious.json file:', error);
        throw error;
    }
}

/**
 * Reads the list of known malicious extension IDs from a local JSON file.
 * Fetches the latest version from GitHub if the cache is expired (10 minutes).
 * @param {vscode.ExtensionContext} context
 * @returns {Promise<string[]>} An array of malicious extension IDs.
 */
async function getMaliciousExtensionsList(context) {
    const maliciousFilePath = path.join(context.extensionPath, 'malicious.json');
    const cacheFilePath = path.join(context.extensionPath, '.malicious-cache');
    
    try {
        // Check if we have a cache file and if it's still valid (10 minutes)
        let shouldFetchFromGitHub = true;
        let cachedData = null;
        
        if (fs.existsSync(cacheFilePath)) {
            try {
                const cacheContent = fs.readFileSync(cacheFilePath, 'utf8');
                const cache = JSON.parse(cacheContent);
                const now = Date.now();
                const tenMinutes = 10 * 60 * 1000; // 10 minutes in milliseconds
                
                if (cache.timestamp && (now - cache.timestamp) < tenMinutes) {
                    shouldFetchFromGitHub = false;
                    cachedData = cache.data;
                    console.log('Using cached malicious extensions list (cache is still valid)');
                } else {
                    console.log('Cache expired, fetching fresh data from GitHub');
                }
            } catch (cacheError) {
                console.warn('Error reading cache file, will fetch from GitHub:', cacheError);
            }
        }
        
        if (shouldFetchFromGitHub) {
            try {
                console.log('Fetching latest malicious extensions list from GitHub...');
                const latestList = await fetchLatestMaliciousList();
                
                // Update the local file
                updateLocalMaliciousFile(context, latestList);
                
                // Update the cache
                const cacheData = {
                    timestamp: Date.now(),
                    data: latestList
                };
                fs.writeFileSync(cacheFilePath, JSON.stringify(cacheData, null, 2), 'utf8');
                
                return latestList;
            } catch (githubError) {
                console.warn('Failed to fetch from GitHub, falling back to local file:', githubError);
                // Fall back to local file if GitHub fetch fails
                shouldFetchFromGitHub = false;
            }
        }
        
        // Use cached data or fall back to local file
        if (cachedData) {
            return cachedData;
        }
        
        // Read from local file as fallback
        if (fs.existsSync(maliciousFilePath)) {
            const fileContent = fs.readFileSync(maliciousFilePath, 'utf8');
            const localList = JSON.parse(fileContent);
            console.log(`Loaded ${localList.length} malicious extensions from local file`);
            return localList;
        } else {
            console.warn('No local malicious.json file found, returning empty list');
            return [];
        }
        
    } catch (error) {
        console.error("Could not read or parse malicious extensions list:", error);
        vscode.window.showErrorMessage("Failed to load malicious extensions list. Check the extension's files and network connection.");
        return [];
    }
}

/**
 * Checks all installed extensions against a malicious list and alerts the user.
 * @param {vscode.ExtensionContext} context
 */
async function checkAndReportMaliciousExtensions(context) {
    const allExtensions = vscode.extensions.all;
    
    try {
        const maliciousList = await getMaliciousExtensionsList(context);

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
    } catch (error) {
        console.error('Error during security audit:', error);
        vscode.window.showErrorMessage('Error during security audit. Check the console for details.');
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