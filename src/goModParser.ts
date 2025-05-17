import * as vscode from 'vscode';
import { GoModule } from './types';

export class GoModParser {
    // Updated regex to handle the block format and indirect dependencies
    private static readonly moduleRegex = /^\s*([^\s]+)\s+([^\s]+)(?:\s+\/\/\s+indirect)?$/;

    public static async parseGoMod(uri: vscode.Uri): Promise<GoModule[]> {
        try {
            const document = await vscode.workspace.openTextDocument(uri);
            const content = document.getText();
            const modules: GoModule[] = [];

            console.log('Parsing go.mod content:', content);

            // Split into lines and process each line
            const lines = content.split('\n');
            console.log('Total lines in go.mod:', lines.length);

            let inRequireBlock = false;

            for (const line of lines) {
                const trimmedLine = line.trim();
                console.log('Processing line:', trimmedLine);

                // Skip empty lines and comments
                if (!trimmedLine || trimmedLine.startsWith('//')) {
                    continue;
                }

                // Check for module declaration
                if (trimmedLine.startsWith('module ')) {
                    continue;
                }

                // Check for go version
                if (trimmedLine.startsWith('go ')) {
                    continue;
                }

                // Check if we're entering a require block
                if (trimmedLine === 'require (') {
                    inRequireBlock = true;
                    console.log('Entering require block');
                    continue;
                }

                // Check if we're leaving a require block
                if (trimmedLine === ')') {
                    inRequireBlock = false;
                    console.log('Leaving require block');
                    continue;
                }

                // Process module lines
                if (inRequireBlock || trimmedLine.startsWith('require ')) {
                    const match = trimmedLine.match(this.moduleRegex);
                    if (match) {
                        const module: GoModule = {
                            path: match[1],
                            version: match[2],
                            indirect: trimmedLine.includes('// indirect')
                        };
                        console.log('Found module:', module);
                        modules.push(module);
                    }
                }
            }

            console.log('Total modules found:', modules.length);
            console.log('Modules:', modules);
            return modules;
        } catch (error) {
            console.error('Error parsing go.mod:', error);
            vscode.window.showErrorMessage(`Failed to parse go.mod: ${error}`);
            return [];
        }
    }

    public static async findGoModFile(): Promise<vscode.Uri | undefined> {
        const files = await vscode.workspace.findFiles('**/go.mod');
        console.log('Found go.mod files:', files.map(f => f.fsPath));
        return files[0];
    }
} 