import * as vscode from "vscode";
import { GoModParser } from './goModParser';
import { DependencyInfo, GoModule } from './types';

export function activate(context: vscode.ExtensionContext) {
  console.log("Go Dependency Threat Scanner is now active!");

  // Register the scan command
  let disposable = vscode.commands.registerCommand('monkeycode.scanDependencies', async () => {
    try {
      const goModUri = await GoModParser.findGoModFile();
      if (!goModUri) {
        vscode.window.showErrorMessage('No go.mod file found in workspace');
        return;
      }

      // Parse dependencies
      const modules = await GoModParser.parseGoMod(goModUri);
      if (modules.length === 0) {
        vscode.window.showInformationMessage('No dependencies found in go.mod');
        return;
      }

      // Show progress
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning Go Dependencies",
        cancellable: true
      }, async (progress) => {
        progress.report({ message: 'Parsing dependencies...' });
        
        // TODO: Implement vulnerability scanning
        // TODO: Implement trust score calculation
        
        // For now, just show the dependencies
        const dependencyList = modules.map(m => `${m.path}@${m.version}`).join('\n');
        vscode.window.showInformationMessage(`Found ${modules.length} dependencies`);
        
        // Create a new untitled document to show results
        const doc = await vscode.workspace.openTextDocument({
          content: `Dependencies found:\n${dependencyList}`,
          language: 'markdown'
        });
        await vscode.window.showTextDocument(doc);
      });

    } catch (error) {
      vscode.window.showErrorMessage(`Error scanning dependencies: ${error}`);
    }
  });

  // Register file watcher for go.mod
  const fileWatcher = vscode.workspace.createFileSystemWatcher('**/go.mod');
  fileWatcher.onDidChange(async (uri) => {
    const config = vscode.workspace.getConfiguration('monkeycode');
    if (config.get('scanOnSave')) {
      vscode.commands.executeCommand('monkeycode.scanDependencies');
    }
  });

  context.subscriptions.push(disposable, fileWatcher);
}

export function deactivate() {}
