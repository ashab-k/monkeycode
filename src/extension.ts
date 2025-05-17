import * as vscode from "vscode";
import { GoModParser } from "./goModParser";
import { VulnerabilityScanner } from "./vulnerabilityScanner";
import { CodeScanner, VulnerableUsage, CodeLocation } from "./codeScanner";
import { GoModule, Vulnerability, DependencyTree } from "./types";
import * as crypto from "crypto";
import axios from "axios";

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
    dependencies: Array<{
      id: string;
      path: string;
      version: string;
      indirect: boolean;
    }>;
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

interface GoModCache {
  hash: string;
  content: string;
  timestamp: string;
  report: ScanReport;
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
    async (forceRescan: boolean = false) => {
      try {
        console.log("Scan command called with forceRescan:", forceRescan);
        if (forceRescan) {
          console.log("Force rescan was requested - this could be from:");
          console.log("1. Explicit force rescan command");
          console.log("2. go.mod file change");
          console.log("3. Manual trigger with force=true parameter");
        }
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

        // Check cache if not forcing rescan
        if (!forceRescan) {
          console.log("Checking cache...");
          const currentHash = await getGoModHash(goModUri);
          console.log("Current go.mod hash:", currentHash);

          const cachedData = context.workspaceState.get("goModCache") as
            | GoModCache
            | undefined;
          console.log("Cached data found:", !!cachedData);
          if (cachedData) {
            console.log("Cached hash:", cachedData.hash);
            console.log("Cache timestamp:", cachedData.timestamp);
          }

          if (cachedData && cachedData.hash === currentHash) {
            console.log("Cache hit! Using cached results");

            // Show the cached report
            const document = await vscode.workspace.openTextDocument({
              content: generateReportFromCache(cachedData.report),
              language: "markdown",
            });
            await vscode.window.showTextDocument(document);

            // Update the JSON report in workspace state
            context.workspaceState.update(
              "lastScanJsonReport",
              cachedData.report
            );

            // Save JSON report to file if configured
            const config = vscode.workspace.getConfiguration("monkeycode");
            if (config.get("saveJsonReport")) {
              const jsonPath = vscode.Uri.joinPath(
                workspaceFolders[0].uri,
                `.monkeycode/reports/scan_${cachedData.report.scanId}.json`
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
                Buffer.from(JSON.stringify(cachedData.report, null, 2))
              );
            }

            vscode.window.showInformationMessage(
              `Using cached scan results from ${new Date(
                cachedData.timestamp
              ).toLocaleString()}`
            );
            return;
          } else {
            console.log("Cache miss - performing new scan");
          }
        } else {
          console.log("Force rescan requested - ignoring cache");
        }

        const progressOptions: vscode.ProgressOptions = {
          location: vscode.ProgressLocation.Notification,
          title: "Scanning Go dependencies...",
          cancellable: true,
        };

        await vscode.window.withProgress(progressOptions, async (progress, token) => {
          token.onCancellationRequested(() => {
            console.log("User cancelled the scan");
            return;
          });

          progress.report({ message: "Parsing go.mod file..." });
          const modules = await GoModParser.parseGoMod(goModUri);

          progress.report({ message: "Scanning for vulnerabilities..." });
          const { vulnerabilities, dependencyTree } =
            await VulnerabilityScanner.scanDependencies(modules);

          progress.report({
            message: "Scanning codebase for vulnerable code...",
            increment: 0
          });
          const usages = await CodeScanner.scanCodebase(
            workspaceFolders[0].uri.fsPath,
            vulnerabilities
          );

          progress.report({
            message: "Generating report...",
            increment: 0
          });
          const report = await generateReport(
            modules,
            vulnerabilities,
            dependencyTree,
            usages
          );

          progress.report({
            message: "Sending report to API...",
            increment: 0
          });
          // Send report to API
          await sendReportToApi(report.json);

          // Cache the results
          console.log("Caching new scan results...");
          const goModContent = await vscode.workspace.fs.readFile(goModUri);
          const cache: GoModCache = {
            hash: await getGoModHash(goModUri),
            content: Buffer.from(goModContent).toString("utf8"),
            timestamp: new Date().toISOString(),
            report: report.json,
          };
          console.log("New cache hash:", cache.hash);
          console.log("New cache timestamp:", cache.timestamp);
          context.workspaceState.update("goModCache", cache);
          console.log("Cache updated in workspace state");

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
        });
      } catch (error) {
        console.error("Error in scan command:", error);
        vscode.window.showErrorMessage(
          `Error scanning dependencies: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  );

  // Add a command to force rescan
  let forceRescanCommand = vscode.commands.registerCommand(
    "monkeycode.forceRescanDependencies",
    () => {
      console.log("Force rescan command explicitly called");
      vscode.commands.executeCommand("monkeycode.scanDependencies", true);
    }
  );

  // Command to show vulnerable code in the current file
  let showVulnerableCodeCommand = vscode.commands.registerCommand(
    "monkeycode.showVulnerableCode",
    async () => {
      try {
        console.log("Show vulnerable code command called");
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
          console.log("No active text editor");
          vscode.window.showInformationMessage(
            "Please open a Go file to show vulnerable code"
          );
          return;
        }

        if (editor.document.languageId !== "go") {
          console.log(
            "Active file is not a Go file:",
            editor.document.languageId
          );
          vscode.window.showInformationMessage(
            "Please open a Go file to show vulnerable code"
          );
          return;
        }

        // Clear any existing decorations first
        console.log("Clearing existing decorations");
        editor.setDecorations(decorationType, []);

        console.log(
          "Showing vulnerable code for file:",
          editor.document.fileName
        );

        const storedReport = context.workspaceState.get(
          "lastScanJsonReport"
        ) as ScanReport | undefined;

        if (!storedReport) {
          console.log("No stored scan report found");
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
          vulnerabilities: storedReport.vulnerabilities.length,
        });

        // Convert JSON report back to the format expected by CodeScanner
        const vulnerabilities = new Map<string, Vulnerability[]>();
        const usages: VulnerableUsage[] = [];

        console.log("Converting stored report to scanner format");
        storedReport.vulnerabilities.forEach((vuln) => {
          console.log("Processing vulnerability:", {
            module: vuln.modulePath,
            id: vuln.vulnerabilityId,
            usages: vuln.usages.length,
          });

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
          });
          vulnerabilities.set(vuln.modulePath, moduleVulns);

          // Add to usages array
          if (vuln.usages.length > 0) {
            // Group usages by file and line to combine multiple usages at the same location
            const locationMap = new Map<string, CodeLocation>();

            vuln.usages.forEach((usage) => {
              const key = `${usage.file}:${usage.line}:${usage.column}`;
              const existingLocation = locationMap.get(key);

              if (existingLocation) {
                // Combine details if we have multiple usages at the same location
                existingLocation.details = `${existingLocation.details}\n${usage.details}`;
              } else {
                // Create a new location with proper details and length
                locationMap.set(key, {
                  file: usage.file,
                  line: usage.line,
                  column: usage.column,
                  length: usage.type === "import" ? vuln.modulePath.length : 20, // Use module path length for imports, default length for others
                  type: usage.type as "import" | "function" | "method",
                  details:
                    usage.details ||
                    `Uses vulnerable package ${vuln.modulePath} (${vuln.vulnerabilityId})`,
                });
              }
            });

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
              },
              locations: Array.from(locationMap.values()),
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
          console.log("No vulnerable code found in this file");
          vscode.window.showInformationMessage(
            "No vulnerable code found in this file"
          );
          return;
        }

        // Create decorations for the current file
        console.log("Creating decorations for file");
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
        console.log("Applying decorations to editor");
        editor.setDecorations(decorationType, decorations);
        console.log("Decorations applied successfully");

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
  if (config.get("watchGoMod", false)) {
    // Default to false
    console.log("Setting up go.mod file watcher...");
    let lastContent: string | undefined;
    let debounceTimer: NodeJS.Timeout | undefined;

    const watcher = vscode.workspace.createFileSystemWatcher("**/go.mod");

    watcher.onDidChange(async (uri) => {
      console.log("go.mod file change detected:", uri.fsPath);

      // Read the current content
      const content = await vscode.workspace.fs.readFile(uri);
      const contentStr = Buffer.from(content).toString("utf8");

      // Only trigger if content actually changed
      if (contentStr !== lastContent) {
        console.log("go.mod content actually changed, scheduling rescan");
        lastContent = contentStr;

        // Clear any existing timer
        if (debounceTimer) {
          clearTimeout(debounceTimer);
        }

        // Debounce the rescan for 1 second
        debounceTimer = setTimeout(() => {
          console.log("Triggering force rescan after debounce");
          vscode.commands.executeCommand("monkeycode.forceRescanDependencies");
        }, 1000);
      } else {
        console.log(
          "go.mod file accessed but content unchanged, skipping rescan"
        );
      }
    });

    context.subscriptions.push(watcher);
  } else {
    console.log("go.mod file watcher is disabled");
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
    forceRescanCommand,
    showVulnerableCodeCommand,
    goFileWatcher,
    editorChangeDisposable
  );
}

async function generateDependencyTree(): Promise<string[]> {
  const lines: string[] = [];
  
  // Get the go.mod file content
  const goModUri = await GoModParser.findGoModFile();
  if (!goModUri) {
    lines.push("No go.mod file found");
    return lines;
  }

  const document = await vscode.workspace.openTextDocument(goModUri);
  const content = document.getText();
  const fileLines = content.split('\n');

  // Parse the go.mod file directly
  const dependencies: { path: string; version: string; indirect: boolean }[] = [];
  let inRequireBlock = false;

  for (const line of fileLines) {
    const trimmedLine = line.trim();
    
    if (trimmedLine === 'require (') {
      inRequireBlock = true;
      continue;
    }
    
    if (trimmedLine === ')') {
      inRequireBlock = false;
      continue;
    }

    if (inRequireBlock) {
      const match = trimmedLine.match(/^\s*([^\s]+)\s+([^\s]+)(?:\s+\/\/\s+indirect)?$/);
      if (match) {
        const [_, path, version] = match;
        dependencies.push({
          path,
          version,
          indirect: trimmedLine.includes('// indirect')
        });
      }
    }
  }

  // Print the dependencies
  lines.push("Dependencies:");
  dependencies.forEach(dep => {
    const indirect = dep.indirect ? " (indirect)" : "";
    lines.push(`- ${dep.path}@${dep.version}${indirect}`);
  });

  return lines;
}

async function generateReport(
  modules: GoModule[],
  vulnerabilities: Map<string, Vulnerability[]>,
  dependencyTree: DependencyTree,
  usages: VulnerableUsage[]
): Promise<{ markdown: string; json: ScanReport }> {
  const parts: string[] = [];
  const scanId = generateHash(Date.now().toString());

  // Add header
  parts.push("# Go Dependency Threat Scan Report\n");
  parts.push(`Scan ID: ${scanId}\n`);
  parts.push(`Timestamp: ${new Date().toISOString()}\n`);

  // Add dependency tree
  parts.push("## Dependency Tree\n");
  parts.push("```\n");
  const treeLines = await generateDependencyTree();
  parts.push(...treeLines);
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
            
            // Add fix information if available
            const vulnWithAffected = vuln as any;
            if (vulnWithAffected.affected && vulnWithAffected.affected.length > 0) {
              const fixInfo = vulnWithAffected.affected[0].ranges?.[0]?.events?.find((e: any) => e.fixed);
              if (fixInfo) {
                parts.push(`- Fixed in version: ${fixInfo.fixed}`);
              }
            }
            
            parts.push("\n" + vuln.details + "\n");
          });
        }
      }
    });
  }

  // Generate JSON report
  const jsonReport: ScanReport = {
    scanId: generateHash(Date.now().toString()),
    timestamp: new Date().toISOString(),
    summary: {
      totalVulnerabilities: totalVulns,
      criticalVulnerabilities: criticalVulns,
      highVulnerabilities: highVulns,
      mediumVulnerabilities: mediumVulns,
      lowVulnerabilities: lowVulns,
      totalUsages: usages.length,
    },
    dependencyTree: Array.from(dependencyTree.entries()).map(([path, node]) => ({
      id: generateHash(`${path}@${node.module.version}`),
      path,
      version: node.module.version,
      indirect: node.module.indirect,
      depth: node.depth,
      dependencies: node.dependencies.map(dep => ({
        id: generateHash(`${dep.path}@${dep.version}`),
        path: dep.path,
        version: dep.version,
        indirect: dep.indirect
      }))
    })),
    vulnerabilities: [],
  };

  // Process vulnerabilities to match exact format
  vulnerabilities.forEach((vulns, modulePath) => {
    const module = modules.find((m) => m.path === modulePath);
    if (!module) return;

    vulns.forEach((vuln) => {
      const vulnUsages = usages.filter(
        (u) => u.module.path === modulePath && u.vulnerability.id === vuln.id
      );

      const usageDetails = vulnUsages.flatMap((usage) =>
        usage.locations.map((location) => ({
          id: generateHash(
            `${vuln.id}:${location.file}:${location.line}:${location.column}`
          ),
          file: location.file,
          line: location.line,
          column: location.column,
          type: location.type,
          details:
            location.details ||
            `Uses vulnerable package ${modulePath} (${vuln.id})`,
        }))
      );

      const vulnerability = {
        id: generateHash(`${modulePath}@${module.version}:${vuln.id}`),
        modulePath,
        moduleVersion: module.version,
        vulnerabilityId: vuln.id,
        severity: normalizeSeverity(vuln.severity),
        summary: vuln.summary,
        details: vuln.details,
        published: vuln.published.toISOString(),
        modified: vuln.modified.toISOString(),
        aliases: vuln.aliases,
        usages: usageDetails,
      };

      // Add affected information if available
      if (vuln.affected) {
        (vulnerability as any).affected = vuln.affected;
      }

      jsonReport.vulnerabilities.push(vulnerability);
    });
  });

  return {
    markdown: parts.join("\n"),
    json: jsonReport,
  };
}

async function getGoModHash(uri: vscode.Uri): Promise<string> {
  const content = await vscode.workspace.fs.readFile(uri);
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function sendReportToApi(report: ScanReport): Promise<void> {
  try {
    const apiUrl = vscode.workspace
      .getConfiguration("monkeycode")
      .get("apiUrl", "http://localhost:4000");
    console.log("Sending report to API:", apiUrl);

    const response = await axios.post(`${apiUrl}/api/scan-reports`, report);
    console.log("API response:", response.data);

    if (response.status === 201) {
      const scanId = response.data.scanId || report.scanId;
      
      // Show completion message first
      vscode.window.showInformationMessage(
        `Scan complete! Report stored with ID: ${scanId}`,
        { modal: false }
      );

      // Then show the view option separately
      const viewOnWeb = "View on Web";
      const action = await vscode.window.showInformationMessage(
        `View the scan report in your browser?`,
        { modal: false },
        viewOnWeb
      );
      
      if (action === viewOnWeb) {
        const webUrl = `http://localhost:3000/scan/${scanId}`;
        vscode.env.openExternal(vscode.Uri.parse(webUrl));
      }
    }
  } catch (error) {
    console.error("Error sending report to API:", error);
    if (axios.isAxiosError(error)) {
      vscode.window.showErrorMessage(
        `Failed to store scan report: ${
          error.response?.data?.error || error.message
        }`
      );
    } else {
      vscode.window.showErrorMessage(
        `Failed to store scan report: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }
}

// Add function to generate markdown from cached report
function generateReportFromCache(report: ScanReport): string {
  const parts: string[] = [];

  // Add header
  parts.push("# Go Dependency Scan Report (Cached)\n");
  parts.push(`Generated: ${new Date(report.timestamp).toLocaleString()}\n`);

  // Add dependency tree
  parts.push("## Dependency Tree\n");
  parts.push("```\n");
  report.dependencyTree.forEach((node) => {
    const indent = "  ".repeat(node.depth);
    const indirect = node.indirect ? " (indirect)" : "";
    parts.push(`${indent}${node.path}@${node.version}${indirect}`);
  });
  parts.push("```\n");

  // Add vulnerability summary
  parts.push("## Vulnerability Summary\n");
  parts.push(`Total Vulnerabilities: ${report.summary.totalVulnerabilities}\n`);
  parts.push(`- Critical: ${report.summary.criticalVulnerabilities}`);
  parts.push(`- High: ${report.summary.highVulnerabilities}`);
  parts.push(`- Medium: ${report.summary.mediumVulnerabilities}`);
  parts.push(`- Low: ${report.summary.lowVulnerabilities}\n`);

  // Add code usage summary
  if (report.summary.totalUsages > 0) {
    parts.push("## Vulnerable Code Usage\n");
    parts.push(
      `Found ${report.summary.totalUsages} vulnerable packages in use:\n`
    );

    // Group usages by file
    const fileUsagesMap = new Map<
      string,
      Array<{
        modulePath: string;
        vulnerabilityId: string;
        severity: string;
        summary: string;
        line: number;
        details: string;
      }>
    >();

    report.vulnerabilities.forEach((vuln) => {
      vuln.usages.forEach((usage) => {
        const fileUsages = fileUsagesMap.get(usage.file) || [];
        fileUsages.push({
          modulePath: vuln.modulePath,
          vulnerabilityId: vuln.vulnerabilityId,
          severity: vuln.severity,
          summary: vuln.summary,
          line: usage.line,
          details: usage.details,
        });
        fileUsagesMap.set(usage.file, fileUsages);
      });
    });

    // Add usage details by file
    for (const [file, usages] of fileUsagesMap) {
      const relativePath = vscode.workspace.asRelativePath(file);
      parts.push(`### ${relativePath}\n`);

      usages.forEach((usage) => {
        parts.push(`- Line ${usage.line}: ${usage.details}`);
        parts.push(`  - Severity: ${usage.severity}`);
        parts.push(`  - ${usage.summary}\n`);
      });
    }
  }

  // Add detailed vulnerability information
  if (report.summary.totalVulnerabilities > 0) {
    parts.push("## Detailed Vulnerabilities\n");
    report.vulnerabilities.forEach((vuln) => {
      parts.push(`### ${vuln.modulePath}@${vuln.moduleVersion}\n`);
      parts.push(`#### ${vuln.severity.toUpperCase()}: ${vuln.summary}`);
      parts.push(`- ID: ${vuln.vulnerabilityId}`);
      if (vuln.aliases.length > 0) {
        parts.push(`- Aliases: ${vuln.aliases.join(", ")}`);
      }
      parts.push(
        `- Published: ${new Date(vuln.published).toLocaleDateString()}`
      );
      parts.push(`- Modified: ${new Date(vuln.modified).toLocaleDateString()}`);
      
      // Add fix information if available
      const vulnWithAffected = vuln as any;
      if (vulnWithAffected.affected && vulnWithAffected.affected.length > 0) {
        const fixInfo = vulnWithAffected.affected[0].ranges?.[0]?.events?.find((e: any) => e.fixed);
        if (fixInfo) {
          parts.push(`- Fixed in version: ${fixInfo.fixed}`);
        }
      }
      
      parts.push("\n" + vuln.details + "\n");
    });
  }

  return parts.join("\n");
}

export function deactivate() {
  // Clean up decorations
  if (decorationType) {
    decorationType.dispose();
  }
}