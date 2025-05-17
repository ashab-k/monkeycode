import axios from "axios";
import { GoModule, DependencyTree, DependencyNode } from "./types";

export class DependencyTreeBuilder {
  public static async buildTree(modules: GoModule[]): Promise<DependencyTree> {
    const tree: DependencyTree = new Map();
    
    // Add root module
    const rootModule: GoModule = {
      path: "github.com/ashab-k/snippetbox",
      version: "v1.0.0",
      indirect: false
    };
    
    // Add root module to tree
    tree.set(rootModule.path, {
      module: rootModule,
      dependencies: modules.filter(m => !m.indirect), // Only direct dependencies at root level
      depth: 0
    });

    // First, add all direct dependencies
    for (const module of modules) {
      if (!module.indirect) {
        tree.set(module.path, {
          module,
          dependencies: [],
          depth: 1
        });
      }
    }

    // Then, add indirect dependencies and link them to their parents
    for (const module of modules) {
      if (module.indirect) {
        // Find the parent module (the one that depends on this indirect dependency)
        const parent = modules.find(m => !m.indirect && module.path.startsWith(m.path));
        if (parent) {
          // Add the indirect dependency to the tree
          tree.set(module.path, {
            module,
            dependencies: [],
            depth: 2
          });

          // Add it to its parent's dependencies
          const parentNode = tree.get(parent.path);
          if (parentNode) {
            parentNode.dependencies.push(module);
          }
        }
      }
    }

    return tree;
  }

  private static async buildDependencyTree(
    module: GoModule,
    tree: DependencyTree,
    depth: number = 0
  ): Promise<void> {
    if (depth > 10) return; // Prevent infinite recursion
    if (tree.has(module.path)) return;

    try {
      const moduleInfo = await this.fetchModuleInfo(module);
      const dependencies = this.extractDependencies(moduleInfo);
      
      // Add module to tree
      tree.set(module.path, {
        module,
        dependencies,
        depth
      });

      // Recursively build tree for direct dependencies
      for (const dep of dependencies) {
        if (!dep.indirect) {
          await this.buildDependencyTree(dep, tree, depth + 1);
        }
      }
    } catch (error) {
      console.error(`Error fetching dependency info for ${module.path}:`, error);
      // Add module to tree even if we can't get its dependencies
      tree.set(module.path, {
        module,
        dependencies: [],
        depth
      });
    }
  }

  private static async fetchModuleInfo(module: GoModule): Promise<any> {
    const response = await axios.get(
      `https://proxy.golang.org/${module.path}/@v/${module.version}.info`,
      {
        headers: { Accept: "application/json" }
      }
    );
    return response.data;
  }

  private static extractDependencies(moduleInfo: any): GoModule[] {
    if (!moduleInfo.Deps) return [];

    return moduleInfo.Deps.map((dep: any) => ({
      path: dep.Path,
      version: dep.Version,
      indirect: dep.Indirect || false
    }));
  }
} 