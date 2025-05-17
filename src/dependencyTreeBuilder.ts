import axios from "axios";
import { GoModule, DependencyTree, DependencyNode } from "./types";

export class DependencyTreeBuilder {
  public static async buildTree(modules: GoModule[]): Promise<DependencyTree> {
    const tree: DependencyTree = new Map();
    
    for (const module of modules) {
      await this.buildDependencyTree(module, tree);
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