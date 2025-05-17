import * as vscode from "vscode";
import { GoModParser } from './goModParser';
import { VulnerabilityScanner } from './vulnerabilityScanner';
import { DependencyInfo, GoModule, ScanResult } from './types';

export function activate(context: vscode.ExtensionContext) {
  console.log("Go Dependency Threat Scanner is now active!");

  // Register the scan command
  let disposable = vscode.commands.registerCommand('monkeycode.scanDependencies', async () => {
    try {
      // Find and parse go.mod
      const goModUri = await GoModParser.findGoModFile();
      if (!goModUri) {
        vscode.window.showErrorMessage('No go.mod file found in workspace');
        return;
      }

      // Show progress
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning Go dependencies...",
        cancellable: false
      }, async (progress) => {
        progress.report({ message: "Parsing go.mod file..." });
        const modules = await GoModParser.parseGoMod(goModUri);
        
        if (modules.length === 0) {
          vscode.window.showWarningMessage('No dependencies found in go.mod');
          return;
        }

        progress.report({ message: "Checking for vulnerabilities..." });
        const vulnerabilities = await VulnerabilityScanner.scanDependencies(modules);

        // Create scan result
        const scanResult: ScanResult = {
          timestamp: new Date(),
          modules: modules.map(module => ({
            module,
            vulnerabilities: vulnerabilities.get(module.path) || []
          })),
          totalVulnerabilities: Array.from(vulnerabilities.values())
            .reduce((sum, vulns) => sum + vulns.length, 0),
          hasCriticalVulnerabilities: Array.from(vulnerabilities.values())
            .some(vulns => vulns.some(v => v.severity === 'critical'))
        };

        // Display results
        await displayScanResults(scanResult);
      });

    } catch (error) {
      console.error('Error during dependency scan:', error);
      vscode.window.showErrorMessage(`Failed to scan dependencies: ${error}`);
    }
  });

  // Watch for go.mod changes if enabled
  const config = vscode.workspace.getConfiguration('monkeycode');
  if (config.get('watchGoMod')) {
    const watcher = vscode.workspace.createFileSystemWatcher('**/go.mod');
    watcher.onDidChange(() => {
      vscode.commands.executeCommand('monkeycode.scanDependencies');
    });
    context.subscriptions.push(watcher);
  }

  context.subscriptions.push(disposable);
}

async function displayScanResults(result: ScanResult) {
  // Create a new untitled document to show results
  const document = await vscode.workspace.openTextDocument({
    content: generateMarkdownReport(result),
    language: 'markdown'
  });
  
  await vscode.window.showTextDocument(document);

  // Show summary notification
  if (result.hasCriticalVulnerabilities) {
    vscode.window.showWarningMessage(
      `Found ${result.totalVulnerabilities} vulnerabilities, including critical ones!`,
      'View Details'
    ).then(selection => {
      if (selection === 'View Details') {
        vscode.window.showTextDocument(document);
      }
    });
  } else if (result.totalVulnerabilities > 0) {
    vscode.window.showInformationMessage(
      `Found ${result.totalVulnerabilities} vulnerabilities.`,
      'View Details'
    ).then(selection => {
      if (selection === 'View Details') {
        vscode.window.showTextDocument(document);
      }
    });
  } else {
    vscode.window.showInformationMessage('No vulnerabilities found in dependencies.');
  }
}

function generateMarkdownReport(result: ScanResult): string {
  const lines: string[] = [
    '# Go Dependency Scan Results',
    `\nScan completed at: ${result.timestamp.toLocaleString()}`,
    `\n## Summary`,
    `- Total dependencies: ${result.modules.length}`,
    `- Total vulnerabilities: ${result.totalVulnerabilities}`,
    `- Critical vulnerabilities: ${result.hasCriticalVulnerabilities ? 'Yes' : 'No'}`,
    '\n## Detailed Results\n'
  ];

  // Group modules by vulnerability status
  const vulnerableModules = result.modules.filter(m => m.vulnerabilities.length > 0);
  const safeModules = result.modules.filter(m => m.vulnerabilities.length === 0);

  if (vulnerableModules.length > 0) {
    lines.push('### Vulnerable Dependencies\n');
    for (const { module, vulnerabilities } of vulnerableModules) {
      lines.push(`#### ${module.path}@${module.version}`);
      if (module.indirect) {
        lines.push('*(indirect dependency)*');
      }
      for (const vuln of vulnerabilities) {
        lines.push(`\n- **${vuln.severity.toUpperCase()}**: ${vuln.summary}`);
        lines.push(`  - ID: ${vuln.id}`);
        if (vuln.aliases.length > 0) {
          lines.push(`  - Aliases: ${vuln.aliases.join(', ')}`);
        }
        lines.push(`  - Published: ${vuln.published.toLocaleDateString()}`);
        lines.push(`  - Details: ${vuln.details}`);
      }
      lines.push('');
    }
  }

  if (safeModules.length > 0) {
    lines.push('### Safe Dependencies\n');
    for (const { module } of safeModules) {
      lines.push(`- ${module.path}@${module.version}${module.indirect ? ' (indirect)' : ''}`);
    }
  }

  return lines.join('\n');
}

export function deactivate() {}
