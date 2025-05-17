import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
  console.log("MonkeyCode extension is now active!");

  // Example command registration
  let disposable = vscode.commands.registerCommand(
    "monkeycode.helloWorld",
    () => {
      vscode.window.showInformationMessage("Hello World from MonkeyCode!");
    }
  );

  context.subscriptions.push(disposable);
}

export function deactivate() {}
