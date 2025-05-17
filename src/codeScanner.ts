import * as vscode from "vscode";
import * as path from "path";
import { GoModule, Vulnerability } from "./types";

export interface CodeLocation {
  file: string;
  line: number;
  column: number;
  length: number;
  type: 'import' | 'function' | 'method';
  details: string;
}

export interface VulnerableUsage {
  module: GoModule;
  vulnerability: Vulnerability;
  locations: CodeLocation[];
}

export class CodeScanner {
  public static async scanCodebase(
    workspaceRoot: string,
    vulnerableModules: Map<string, Vulnerability[]>
  ): Promise<VulnerableUsage[]> {
    console.log('Starting code scan in:', workspaceRoot);
    
    const usages = new Map<string, VulnerableUsage>();
    const goFiles = await this.findGoFiles(workspaceRoot);
    console.log('Found', goFiles.length, 'Go files to scan');

    // Process files in batches to avoid blocking
    const batchSize = 10;
    for (let i = 0; i < goFiles.length; i += batchSize) {
      const batch = goFiles.slice(i, i + batchSize);
      await Promise.all(batch.map(async (file) => {
        try {
          // Skip test files
          if (file.endsWith('_test.go')) {
            return;
          }

          const fileContent = await vscode.workspace.fs.readFile(vscode.Uri.file(file));
          const content = Buffer.from(fileContent).toString('utf8');
          
          // Find all imports and their locations
          const imports = this.findImports(content, file);
          
          // Check each import against vulnerable modules
          for (const [importPath, locations] of imports) {
            const vulns = vulnerableModules.get(importPath);
            if (vulns) {
              for (const vuln of vulns) {
                const key = `${importPath}:${vuln.id}`;
                const existingUsage = usages.get(key);
                
                if (existingUsage) {
                  existingUsage.locations.push(...locations);
                } else {
                  usages.set(key, {
                    module: { path: importPath, version: '', indirect: false },
                    vulnerability: vuln,
                    locations: locations
                  });
                }
              }
            }
          }

          // Find function calls to vulnerable packages
          const functionCalls = this.findFunctionCalls(content, file, imports);
          
          for (const [importPath, calls] of functionCalls) {
            const vulns = vulnerableModules.get(importPath);
            if (vulns) {
              for (const vuln of vulns) {
                const key = `${importPath}:${vuln.id}`;
                const existingUsage = usages.get(key);
                
                if (existingUsage) {
                  existingUsage.locations.push(...calls);
                } else {
                  usages.set(key, {
                    module: { path: importPath, version: '', indirect: false },
                    vulnerability: vuln,
                    locations: calls
                  });
                }
              }
            }
          }
        } catch (error) {
          console.error(`Error scanning file ${file}:`, error);
        }
      }));
    }

    const results = Array.from(usages.values());
    console.log('\nScan complete. Found usages:', results.length);
    results.forEach(usage => {
      console.log(`- ${usage.module.path}: ${usage.vulnerability.id} (${usage.locations.length} locations)`);
      const uniqueFiles = new Set(usage.locations.map(l => l.file));
      console.log(`  Found in ${uniqueFiles.size} files:`, Array.from(uniqueFiles));
    });

    return results;
  }

  private static async findGoFiles(root: string): Promise<string[]> {
    const pattern = new vscode.RelativePattern(root, '**/*.go');
    const files = await vscode.workspace.findFiles(pattern, '**/vendor/**');
    return files.map(f => f.fsPath);
  }

  private static findImports(content: string, file: string): Map<string, CodeLocation[]> {
    const imports = new Map<string, CodeLocation[]>();
    const lines = content.split('\n');
    
    // Simple regex-based import finder
    // This could be improved with proper Go AST parsing
    const importRegex = /^import\s+(?:"([^"]+)"|`([^`]+)`|\(([\s\S]*?)\))/gm;
    let match;

    while ((match = importRegex.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const importBlock = match[0];
      
      // Handle different import formats
      if (match[1] || match[2]) {
        // Single import
        const importPath = match[1] || match[2];
        const column = match.index - content.lastIndexOf('\n', match.index);
        const locations = imports.get(importPath) || [];
        locations.push({
          file,
          line,
          column,
          length: importPath.length,
          type: 'import',
          details: `Imports vulnerable package ${importPath}`
        });
        imports.set(importPath, locations);
      } else if (match[3]) {
        // Multiple imports in parentheses
        const importBlock = match[3];
        const importLines = importBlock.split('\n');
        
        for (const importLine of importLines) {
          const importMatch = importLine.match(/"([^"]+)"|`([^`]+)`/);
          if (importMatch) {
            const importPath = importMatch[1] || importMatch[2];
            const lineNum = line + importLines.indexOf(importLine);
            const column = importLine.indexOf(importPath);
            if (column >= 0) {  // Only add if we found the import path
              const locations = imports.get(importPath) || [];
              locations.push({
                file,
                line: lineNum,
                column,
                length: importPath.length,
                type: 'import',
                details: `Imports vulnerable package ${importPath}`
              });
              imports.set(importPath, locations);
            }
          }
        }
      }
    }

    return imports;
  }

  private static findFunctionCalls(
    content: string,
    file: string,
    imports: Map<string, CodeLocation[]>
  ): Map<string, CodeLocation[]> {
    const calls = new Map<string, CodeLocation[]>();
    const lines = content.split('\n');

    // For each imported package, look for its usage
    for (const [importPath, importLocations] of imports) {
      const packageName = this.getPackageName(importPath);
      if (!packageName) continue;

      // Look for function calls using the package
      const callRegex = new RegExp(`\\b${packageName}\\.[a-zA-Z0-9_]+\\b`, 'g');
      let match;

      while ((match = callRegex.exec(content)) !== null) {
        const line = content.substring(0, match.index).split('\n').length;
        const column = match.index - content.lastIndexOf('\n', match.index);
        const locations = calls.get(importPath) || [];
        
        locations.push({
          file,
          line,
          column,
          length: match[0].length,
          type: 'function',
          details: `Calls function ${match[0]} from vulnerable package ${importPath}`
        });
        
        calls.set(importPath, locations);
      }
    }

    return calls;
  }

  private static getPackageName(importPath: string): string | null {
    // Handle different import path formats
    const parts = importPath.split('/');
    if (parts.length === 0) return null;

    // Handle vanity imports and standard library
    const lastPart = parts[parts.length - 1];
    if (lastPart.includes('.')) {
      // Handle vanity imports like github.com/user/repo
      return lastPart.split('.')[0];
    }
    return lastPart;
  }

  public static createDecorations(usages: VulnerableUsage[], currentFile?: string): vscode.DecorationOptions[] {
    const decorations: vscode.DecorationOptions[] = [];
    console.log('Creating decorations for', usages.length, 'usages', currentFile ? `in ${currentFile}` : '');

    // Group usages by file and line to prevent duplicates
    const fileLineMap = new Map<string, Map<number, {
      usage: VulnerableUsage;
      locations: CodeLocation[];
    }>>();

    for (const usage of usages) {
      console.log('Processing usage:', usage.module.path, usage.vulnerability.id);
      for (const location of usage.locations) {
        // Skip empty locations
        if (!location.details || location.length === 0) {
          console.log('  Skipping empty location at line:', location.line);
          continue;
        }

        // Skip locations from other files if we're filtering by current file
        if (currentFile && location.file !== currentFile) {
          console.log('  Skipping location from different file:', location.file);
          continue;
        }

        // Initialize file map if needed
        if (!fileLineMap.has(location.file)) {
          fileLineMap.set(location.file, new Map());
        }
        const lineMap = fileLineMap.get(location.file)!;
        
        // Get or create the entry for this line
        const existing = lineMap.get(location.line);
        if (existing) {
          // Add this location to the existing entry if it's not already there
          if (!existing.locations.some(l => 
            l.type === location.type && 
            l.column === location.column && 
            l.length === location.length
          )) {
            existing.locations.push(location);
          }
        } else {
          // Create a new entry for this line
          lineMap.set(location.line, {
            usage,
            locations: [location]
          });
        }
      }
    }

    // Create decorations from the deduplicated map
    for (const [file, lineMap] of fileLineMap) {
      // Skip other files if we're filtering by current file
      if (currentFile && file !== currentFile) {
        continue;
      }

      for (const [line, { usage, locations }] of lineMap) {
        console.log('  Creating decoration for:', file, 'line:', line, 'with', locations.length, 'locations');
        
        // Use the first location for the range (they should all be on the same line)
        const firstLocation = locations[0];
        const range = new vscode.Range(
          new vscode.Position(line - 1, firstLocation.column),
          new vscode.Position(line - 1, firstLocation.column + firstLocation.length)
        );

        const hoverMessage = new vscode.MarkdownString();
        const severity = typeof usage.vulnerability.severity === 'string' ? 
          usage.vulnerability.severity.toUpperCase() : 
          'UNKNOWN';
        hoverMessage.appendMarkdown(`### ${severity} Vulnerability\n\n`);
        hoverMessage.appendMarkdown(`**${usage.vulnerability.summary}**\n\n`);
        hoverMessage.appendMarkdown(`Package: ${usage.module.path}\n\n`);
        
        // Add details about all usages at this line
        if (locations.length > 1) {
          hoverMessage.appendMarkdown('**Usage at this location:**\n');
          locations.forEach(loc => {
            hoverMessage.appendMarkdown(`- ${loc.details}\n`);
          });
          hoverMessage.appendMarkdown('\n');
        }
        
        hoverMessage.appendMarkdown(usage.vulnerability.details);

        const decoration = {
          range,
          hoverMessage,
          renderOptions: {
            after: {
              contentText: `⚠️ ${usage.vulnerability.severity}`,
              color: this.getSeverityColor(usage.vulnerability.severity)
            }
          }
        };
        decorations.push(decoration);
      }
    }

    console.log('Created total decorations:', decorations.length);
    return decorations;
  }

  private static getSeverityColor(severity: string): vscode.ThemeColor {
    switch (severity) {
      case 'critical':
        return new vscode.ThemeColor('errorForeground');
      case 'high':
        return new vscode.ThemeColor('charts.red');
      case 'medium':
        return new vscode.ThemeColor('charts.orange');
      case 'low':
        return new vscode.ThemeColor('charts.yellow');
      default:
        return new vscode.ThemeColor('charts.grey');
    }
  }
} 