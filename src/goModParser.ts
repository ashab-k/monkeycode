import * as vscode from 'vscode';
import { GoModule } from './types';

export class GoModParser {
    private static readonly requireRegex = /^\s*require\s+([^\s]+)\s+([^\s]+)(?:\s+\/\/\s+indirect)?$/;

    public static async parseGoMod(uri: vscode.Uri): Promise<GoModule[]> {
        try {
            const document = await vscode.workspace.openTextDocument(uri);
            const content = document.getText();
            const modules: GoModule[] = [];

            // Split into lines and process each line
            const lines = content.split('\n');
            for (const line of lines) {
                const match = line.match(this.requireRegex);
                if (match) {
                    modules.push({
                        path: match[1],
                        version: match[2],
                        indirect: line.includes('// indirect')
                    });
                }
            }

            return modules;
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to parse go.mod: ${error}`);
            return [];
        }
    }

    public static async findGoModFile(): Promise<vscode.Uri | undefined> {
        const files = await vscode.workspace.findFiles('**/go.mod');
        return files[0]; // Return the first go.mod found
    }
} 