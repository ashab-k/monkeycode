import * as vscode from "vscode";
import { GoModParser } from "./goModParser";
import { VulnerabilityScanner } from "./vulnerabilityScanner";
import { GoModule, Vulnerability, DependencyTree } from "./types";

export function activate(context: vscode.ExtensionContext) {
  console.log('Go Dependency Threat Scanner is now active');

  let disposable = vscode.commands.registerCommand('monkeycode.scanDependencies', async () => {
    try {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders) {
        vscode.window.showErrorMessage("No workspace folder open");
        return;
      }

      const goModUri = await GoModParser.findGoModFile();
      if (!goModUri) {
        vscode.window.showErrorMessage("No go.mod file found in workspace");
        return;
      }

      const progressOptions: vscode.ProgressOptions = {
        location: vscode.ProgressLocation.Notification,
        title: "Scanning Go dependencies...",
        cancellable: false,
      };

      await vscode.window.withProgress(progressOptions, async (progress) => {
        progress.report({ message: "Parsing go.mod file..." });
        const modules = await GoModParser.parseGoMod(goModUri);

        progress.report({ message: "Scanning for vulnerabilities..." });
        const { vulnerabilities, dependencyTree } = await VulnerabilityScanner.scanDependencies(modules);

        // Create a new untitled document to show results
        const document = await vscode.workspace.openTextDocument({
          content: generateReport(modules, vulnerabilities, dependencyTree),
          language: "markdown",
        });

        await vscode.window.showTextDocument(document);
      });
    } catch (error) {
      vscode.window.showErrorMessage(
        `Error scanning dependencies: ${error instanceof Error ? error.message : String(error)}`
      );
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

function generateReport(
  modules: GoModule[],
  vulnerabilities: Map<string, Vulnerability[]>,
  dependencyTree: DependencyTree
): string {
  const parts: string[] = [];

  // Add header
  parts.push("# Go Dependency Scan Report\n");
  parts.push(`Generated: ${new Date().toLocaleString()}\n`);

  // Add dependency tree
  parts.push("## Dependency Tree\n");
  parts.push("```\n");
  for (const [path, node] of dependencyTree) {
    const indent = "  ".repeat(node.depth);
    const version = node.module.version;
    const indirect = node.module.indirect ? " (indirect)" : "";
    parts.push(`${indent}${path}@${version}${indirect}`);
  }
  parts.push("```\n");

  // Add vulnerability summary
  let totalVulns = 0;
  let criticalVulns = 0;
  let highVulns = 0;
  let mediumVulns = 0;
  let lowVulns = 0;

  vulnerabilities.forEach((vulns) => {
    totalVulns += vulns.length;
    vulns.forEach((vuln) => {
      switch (vuln.severity) {
        case "critical":
          criticalVulns++;
          break;
        case "high":
          highVulns++;
          break;
        case "medium":
          mediumVulns++;
          break;
        case "low":
          lowVulns++;
          break;
      }
    });
  });

  parts.push("## Vulnerability Summary\n");
  parts.push(`Total Vulnerabilities: ${totalVulns}\n`);
  parts.push(`- Critical: ${criticalVulns}`);
  parts.push(`- High: ${highVulns}`);
  parts.push(`- Medium: ${mediumVulns}`);
  parts.push(`- Low: ${lowVulns}\n`);

  // Add detailed vulnerability information
  if (totalVulns > 0) {
    parts.push("## Detailed Vulnerabilities\n");
    vulnerabilities.forEach((vulns, modulePath) => {
      if (vulns.length > 0) {
        const module = modules.find(m => m.path === modulePath);
        if (module) {
          parts.push(`### ${modulePath}@${module.version}\n`);
          vulns.forEach((vuln) => {
            parts.push(`#### ${vuln.severity.toUpperCase()}: ${vuln.summary}`);
            parts.push(`- ID: ${vuln.id}`);
            if (vuln.aliases.length > 0) {
              parts.push(`- Aliases: ${vuln.aliases.join(", ")}`);
            }
            parts.push(`- Published: ${vuln.published.toLocaleDateString()}`);
            parts.push(`- Modified: ${vuln.modified.toLocaleDateString()}`);
            parts.push("\n" + vuln.details + "\n");
          });
        }
      }
    });
  }

  return parts.join("\n");
}

export function deactivate() {}
