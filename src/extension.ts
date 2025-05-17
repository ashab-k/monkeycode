import * as vscode from "vscode";
import { GoModParser } from "./goModParser";
import { VulnerabilityScanner } from "./vulnerabilityScanner";
import { CodeScanner, VulnerableUsage, CodeLocation } from "./codeScanner";
import { GoModule, Vulnerability, DependencyTree } from "./types";
import * as crypto from "crypto";

let decorationType: vscode.TextEditorDecorationType;

// Add type for severity
type Severity = "low" | "medium" | "high" | "critical" | "unknown";

interface ScanReport {
  scanId: string;
  timestamp: string;
  summary: {
    totalVulnerabilities: number;
    criticalVulnerabilities: number;
    highVulnerabilities: number;
    mediumVulnerabilities: number;
    lowVulnerabilities: number;
    totalUsages: number;
  };
  dependencyTree: Array<{
    id: string;
    path: string;
    version: string;
    indirect: boolean;
    depth: number;
  }>;
  vulnerabilities: Array<{
    id: string;
    modulePath: string;
    moduleVersion: string;
    vulnerabilityId: string;
    severity: Severity;
    summary: string;
    details: string;
    published: string;
    modified: string;
    aliases: string[];
    usages: Array<{
      id: string;
      file: string;
      line: number;
      column: number;
      type: string;
      details: string;
    }>;
  }>;
}

function generateHash(input: string): string {
  return crypto
    .createHash("sha256")
    .update(input)
    .digest("hex")
    .substring(0, 16);
}

function normalizeSeverity(severity: string): Severity {
  const normalized = severity.toLowerCase();
  if (
    normalized === "unknown" ||
    normalized === "critical" ||
    normalized === "high" ||
    normalized === "medium" ||
    normalized === "low"
  ) {
    return normalized;
  }
  return "unknown";
}

export function activate(context: vscode.ExtensionContext) {
  console.log("Go Dependency Threat Scanner is now active");

  // Create decoration type for vulnerable code
  decorationType = vscode.window.createTextEditorDecorationType({
    // Use a more subtle background color
    backgroundColor: "rgba(var(--vscode-editorWarning-foreground), 0.1)",
    // Use a solid border instead of squiggly
    border: "1px solid",
    borderColor: new vscode.ThemeColor("editorWarning.foreground"),
    // Add a margin to the right of the text
    after: {
      margin: "0 0 0 1em",
      // Add a warning symbol with severity
      contentText: "⚠️",
      color: new vscode.ThemeColor("editorWarning.foreground"),
      fontWeight: "bold",
    },
    // Add a gutter icon
    gutterIconPath: vscode.Uri.parse(
      "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggMUM0LjEzNCAxIDEgNC4xMzQgMSA4czMuMTM0IDcgNyA3IDctMy4xMzQgNy03UzExLjg2NiAxIDggMXptMCAxM2MtMy4zMTQgMC02LTIuNjg2LTYtNnMyLjY4Ni02IDYtNiA2IDIuNjg2IDYgNi0yLjY4NiA2LTYgNnptMC0xMGMtLjU1MiAwLTEgLjQ0OC0xIDF2NGMwIC41NTIuNDQ4IDEgMSAxcy0xLS40NDgtMS0xVjVjMC0uNTUyLjQ0OC0xIDEtMXptMCA4Yy41NTIgMCAxIC40NDggMSAxcy0uNDQ4IDEtMSAxLTEtLjQ0OC0xLTEgLjQ0OC0xIDEtMXoiIGZpbGw9ImN1cnJlbnRDb2xvciIvPjwvc3ZnPg=="
    ),
    gutterIconSize: "contain",
    // Add a hover message
    overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    // Add a light squiggly underline
    textDecoration:
      "none; border-bottom: 1px wavy var(--vscode-editorWarning-foreground)",
  });

  // Command to scan dependencies and generate report
  let scanCommand = vscode.commands.registerCommand(
    "monkeycode.scanDependencies",
    async () => {
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
          const { vulnerabilities, dependencyTree } =
            await VulnerabilityScanner.scanDependencies(modules);

          // Scan codebase for vulnerable code usage
          progress.report({
            message: "Scanning codebase for vulnerable code...",
          });
          const usages = await CodeScanner.scanCodebase(
            workspaceFolders[0].uri.fsPath,
            vulnerabilities
          );

          const report = generateReport(
            modules,
            vulnerabilities,
            dependencyTree,
            usages
          );

          // Store the JSON report in workspace state
          context.workspaceState.update("lastScanJsonReport", report.json);

          // Create a new untitled document to show markdown results
          const document = await vscode.workspace.openTextDocument({
            content: report.markdown,
            language: "markdown",
          });

          await vscode.window.showTextDocument(document);

          // Save JSON report to a file if configured
          const config = vscode.workspace.getConfiguration("monkeycode");
          if (config.get("saveJsonReport")) {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (workspaceFolders) {
              const jsonPath = vscode.Uri.joinPath(
                workspaceFolders[0].uri,
                `.monkeycode/reports/scan_${report.json.scanId}.json`
              );

              // Ensure directory exists
              await vscode.workspace.fs.createDirectory(
                vscode.Uri.joinPath(
                  workspaceFolders[0].uri,
                  ".monkeycode/reports"
                )
              );

              // Write JSON file
              await vscode.workspace.fs.writeFile(
                jsonPath,
                Buffer.from(JSON.stringify(report.json, null, 2))
              );

              vscode.window.showInformationMessage(
                `JSON report saved to ${vscode.workspace.asRelativePath(
                  jsonPath
                )}`
              );
            }
          }

          // Show a message with a link to view the JSON in the Output panel
          const outputChannel =
            vscode.window.createOutputChannel("MonkeyCode Scan");
          outputChannel.appendLine("=== Scan Report JSON ===");
          outputChannel.appendLine(JSON.stringify(report.json, null, 2));
          outputChannel.show();
        });
      } catch (error) {
        vscode.window.showErrorMessage(
          `Error scanning dependencies: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  );

  // Command to show vulnerable code in the current file
  let showVulnerableCodeCommand = vscode.commands.registerCommand(
    "monkeycode.showVulnerableCode",
    async () => {
      try {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
          vscode.window.showInformationMessage(
            "Please open a Go file to show vulnerable code"
          );
          return;
        }

        if (editor.document.languageId !== "go") {
          vscode.window.showInformationMessage(
            "Please open a Go file to show vulnerable code"
          );
          return;
        }

        // Clear any existing decorations first
        editor.setDecorations(decorationType, []);

        console.log(
          "Showing vulnerable code for file:",
          editor.document.fileName
        );

        const storedReport = context.workspaceState.get(
          "lastScanJsonReport"
        ) as ScanReport | undefined;

        if (!storedReport) {
          vscode.window.showInformationMessage(
            'Please run "Scan Dependencies" first to get vulnerability information'
          );
          return;
        }

        console.log("Last scan report found:", {
          scanId: storedReport.scanId,
          timestamp: storedReport.timestamp,
          totalVulnerabilities: storedReport.summary.totalVulnerabilities,
          totalUsages: storedReport.summary.totalUsages,
        });

        // Convert JSON report back to the format expected by CodeScanner
        const vulnerabilities = new Map<string, Vulnerability[]>();
        const usages: VulnerableUsage[] = [];

        storedReport.vulnerabilities.forEach((vuln) => {
          // Add to vulnerabilities map
          const moduleVulns = vulnerabilities.get(vuln.modulePath) || [];
          moduleVulns.push({
            id: vuln.vulnerabilityId,
            severity: normalizeSeverity(vuln.severity),
            summary: vuln.summary,
            details: vuln.details,
            published: new Date(vuln.published),
            modified: new Date(vuln.modified),
            aliases: vuln.aliases,
            affectedVersions: [], // Add empty array since it's optional
          });
          vulnerabilities.set(vuln.modulePath, moduleVulns);

          // Add to usages array
          if (vuln.usages.length > 0) {
            usages.push({
              module: {
                path: vuln.modulePath,
                version: vuln.moduleVersion,
                indirect: false,
              },
              vulnerability: {
                id: vuln.vulnerabilityId,
                severity: normalizeSeverity(vuln.severity),
                summary: vuln.summary,
                details: vuln.details,
                published: new Date(vuln.published),
                modified: new Date(vuln.modified),
                aliases: vuln.aliases,
                affectedVersions: [], // Add empty array since it's optional
              },
              locations: vuln.usages.map((usage) => ({
                file: usage.file,
                line: usage.line,
                column: usage.column,
                length: 0,
                type: usage.type as "import" | "function" | "method",
                details: usage.details,
              })),
            });
          }
        });

        // Filter usages for the current file
        const fileUsages = usages.filter((usage) =>
          usage.locations.some((loc) => loc.file === editor.document.fileName)
        );

        console.log("Found usages for current file:", {
          fileName: editor.document.fileName,
          usageCount: fileUsages.length,
          usages: fileUsages.map((usage) => ({
            module: usage.module.path,
            vulnerability: usage.vulnerability.id,
            severity: usage.vulnerability.severity,
            locations: usage.locations.map((loc) => ({
              line: loc.line,
              type: loc.type,
              details: loc.details,
            })),
          })),
        });

        if (fileUsages.length === 0) {
          vscode.window.showInformationMessage(
            "No vulnerable code found in this file"
          );
          return;
        }

        // Create decorations for the current file
        const decorations = CodeScanner.createDecorations(
          fileUsages,
          editor.document.fileName
        );
        console.log("Created decorations:", {
          count: decorations.length,
          decorations: decorations.map((d) => ({
            range: {
              start: {
                line: d.range.start.line + 1,
                character: d.range.start.character,
              },
              end: {
                line: d.range.end.line + 1,
                character: d.range.end.character,
              },
            },
            severity: (d.renderOptions?.after as any)?.contentText,
            hoverMessage:
              typeof d.hoverMessage === "string"
                ? d.hoverMessage
                : Array.isArray(d.hoverMessage)
                ? d.hoverMessage.join("\n")
                : d.hoverMessage instanceof vscode.MarkdownString
                ? d.hoverMessage.value
                : "No hover message",
          })),
        });

        // Apply decorations to the current editor
        editor.setDecorations(decorationType, decorations);
        console.log("Applied decorations to editor");

        // Show a message with the timestamp of the last scan
        const lastScanDate = new Date(storedReport.timestamp).toLocaleString();
        vscode.window.showInformationMessage(
          `Showing vulnerable code (from scan at ${lastScanDate}). Run "Scan Dependencies" to update.`
        );
      } catch (error) {
        console.error("Error showing vulnerable code:", error);
        vscode.window.showErrorMessage(
          `Error showing vulnerable code: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  );

  // Watch for go.mod changes if enabled
  const config = vscode.workspace.getConfiguration("monkeycode");
  if (config.get("watchGoMod")) {
    const watcher = vscode.workspace.createFileSystemWatcher("**/go.mod");
    watcher.onDidChange(() => {
      vscode.commands.executeCommand("monkeycode.scanDependencies");
    });
    context.subscriptions.push(watcher);
  }

  // Watch for Go file changes to clear decorations
  const goFileWatcher = vscode.workspace.createFileSystemWatcher("**/*.go");

  // Clear decorations when switching editors
  const editorChangeDisposable = vscode.window.onDidChangeActiveTextEditor(
    (editor) => {
      if (editor) {
        editor.setDecorations(decorationType, []);
      }
    }
  );

  goFileWatcher.onDidChange(async (uri) => {
    // Clear decorations when Go files change
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document.uri.fsPath === uri.fsPath) {
      editor.setDecorations(decorationType, []);
    }
  });

  goFileWatcher.onDidDelete(async (uri) => {
    // Clear decorations when Go files are deleted
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document.uri.fsPath === uri.fsPath) {
      editor.setDecorations(decorationType, []);
    }
  });

  context.subscriptions.push(
    scanCommand,
    showVulnerableCodeCommand,
    goFileWatcher,
    editorChangeDisposable
  );
}

function generateReport(
  modules: GoModule[],
  vulnerabilities: Map<string, Vulnerability[]>,
  dependencyTree: DependencyTree,
  usages: VulnerableUsage[]
): { markdown: string; json: ScanReport } {
  const parts: string[] = [];
  const scanId = generateHash(Date.now().toString());
  const timestamp = new Date().toISOString();

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

  // Add code usage summary
  if (usages.length > 0) {
    parts.push("## Vulnerable Code Usage\n");
    parts.push(`Found ${usages.length} vulnerable packages in use:\n`);

    // Group usages by file
    const fileUsagesMap = new Map<
      string,
      Array<{ usage: VulnerableUsage; location: CodeLocation }>
    >();
    usages.forEach((usage) => {
      usage.locations.forEach((location: CodeLocation) => {
        const fileUsages = fileUsagesMap.get(location.file) || [];
        fileUsages.push({ usage, location });
        fileUsagesMap.set(location.file, fileUsages);
      });
    });

    // Add usage details by file
    for (const [file, locations] of fileUsagesMap) {
      const relativePath = vscode.workspace.asRelativePath(file);
      parts.push(`### ${relativePath}\n`);

      locations.forEach(({ usage, location }) => {
        parts.push(`- Line ${location.line}: ${location.details}`);
        parts.push(`  - Severity: ${usage.vulnerability.severity}`);
        parts.push(`  - ${usage.vulnerability.summary}\n`);
      });
    }
  }

  // Add detailed vulnerability information
  if (totalVulns > 0) {
    parts.push("## Detailed Vulnerabilities\n");
    vulnerabilities.forEach((vulns, modulePath) => {
      if (vulns.length > 0) {
        const module = modules.find((m) => m.path === modulePath);
        if (module) {
          parts.push(`### ${modulePath}@${module.version}\n`);
          vulns.forEach((vuln) => {
            const severity =
              typeof vuln.severity === "string"
                ? vuln.severity.toUpperCase()
                : "UNKNOWN";
            parts.push(`#### ${severity}: ${vuln.summary}`);
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

  // Generate JSON report
  const jsonReport: ScanReport = {
    scanId,
    timestamp,
    summary: {
      totalVulnerabilities: totalVulns,
      criticalVulnerabilities: criticalVulns,
      highVulnerabilities: highVulns,
      mediumVulnerabilities: mediumVulns,
      lowVulnerabilities: lowVulns,
      totalUsages: usages.length,
    },
    dependencyTree: Array.from(dependencyTree.entries()).map(
      ([path, node]) => ({
        id: generateHash(`${path}@${node.module.version}`),
        path,
        version: node.module.version,
        indirect: node.module.indirect,
        depth: node.depth,
      })
    ),
    vulnerabilities: [],
  };

  // Process vulnerabilities and their usages
  vulnerabilities.forEach((vulns, modulePath) => {
    const module = modules.find((m) => m.path === modulePath);
    if (!module) return;

    vulns.forEach((vuln) => {
      const vulnId = generateHash(`${modulePath}@${module.version}:${vuln.id}`);
      const vulnUsages = usages.filter(
        (u) => u.module.path === modulePath && u.vulnerability.id === vuln.id
      );

      const usageDetails = vulnUsages.flatMap((usage) =>
        usage.locations.map((location) => ({
          id: generateHash(
            `${vulnId}:${location.file}:${location.line}:${location.column}`
          ),
          file: location.file,
          line: location.line,
          column: location.column,
          type: location.type,
          details: location.details,
        }))
      );

      jsonReport.vulnerabilities.push({
        id: vulnId,
        modulePath,
        moduleVersion: module.version,
        vulnerabilityId: vuln.id,
        severity: normalizeSeverity(
          typeof vuln.severity === "string" ? vuln.severity : "unknown"
        ),
        summary: vuln.summary,
        details: vuln.details,
        published: vuln.published.toISOString(),
        modified: vuln.modified.toISOString(),
        aliases: vuln.aliases,
        usages: usageDetails,
      });
    });
  });

  return {
    markdown: parts.join("\n"),
    json: jsonReport,
  };
}

export function deactivate() {
  // Clean up decorations
  if (decorationType) {
    decorationType.dispose();
  }
}
