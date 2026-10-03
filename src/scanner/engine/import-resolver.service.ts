import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { ResolvedFile } from './types';

@Injectable()
export class ImportResolverService {
  private readonly logger = new Logger(ImportResolverService.name);

  private toPosix(p: string): string {
    return p.replace(/\\/g, '/');
  }

  /**
   * Resolves a project starting from entry file path or virtual files map.
   * If a virtualFiles map is provided (e.g. from a GitHub repository), all protocol
   * contracts in the scope are resolved so that both entrypoint imports and standalone
   * contracts are included in the analysis.
   */
  async resolveProject(
    entryFilePath: string,
    rawContent?: string,
    remappings: Record<string, string> = {},
    virtualFiles: Map<string, string> = new Map(),
  ): Promise<Map<string, ResolvedFile>> {
    const fileMap = new Map<string, ResolvedFile>();
    const visited = new Set<string>();

    // 1. Resolve entry file and its transitive import hierarchy
    if (entryFilePath) {
      await this.resolveRecursive(entryFilePath, rawContent, fileMap, visited, 0, remappings, virtualFiles);
    }

    // 2. Also resolve any remaining protocol smart contracts in the repository scope (excluding tests/mocks)
    for (const [vPath, vContent] of virtualFiles.entries()) {
      const posixPath = this.toPosix(vPath);
      const lower = posixPath.toLowerCase();
      const isTestOrMock =
        lower.endsWith('.t.sol') ||
        lower.includes('/test/') ||
        lower.includes('/tests/') ||
        lower.includes('/mock/') ||
        lower.includes('/mocks/');

      if (!isTestOrMock && !visited.has(posixPath) && vPath.endsWith('.sol')) {
        await this.resolveRecursive(posixPath, vContent, fileMap, visited, 0, remappings, virtualFiles);
      }
    }

    return fileMap;
  }

  private async resolveRecursive(
    filePath: string,
    rawContent: string | undefined,
    fileMap: Map<string, ResolvedFile>,
    visited: Set<string>,
    depth: number,
    remappings: Record<string, string>,
    virtualFiles: Map<string, string>,
  ): Promise<void> {
    const posixPath = this.toPosix(filePath);
    if (visited.has(posixPath)) return;
    visited.add(posixPath);

    if (depth > 50) {
      this.logger.warn(`Import depth limit (50) exceeded at ${posixPath}. Stopping branch.`);
      return;
    }

    let content = rawContent ?? this.lookupVirtualFile(posixPath, virtualFiles);

    // Fallback to local disk if running locally or cloned
    if (content === undefined && fs.existsSync(posixPath)) {
      try {
        content = fs.readFileSync(posixPath, 'utf-8');
      } catch (err: any) {
        this.logger.error(`Failed to read file ${posixPath}: ${err.message}`);
      }
    }

    if (!content) {
      this.logger.debug(`No content found for file: ${posixPath}`);
      return;
    }

    const imports = this.extractImports(content);
    fileMap.set(posixPath, { filePath: posixPath, content, imports });

    const baseDir = path.posix.dirname(posixPath);
    for (const imp of imports) {
      const resolvedImportPath = this.resolveImportPath(baseDir, imp, remappings, virtualFiles);
      if (resolvedImportPath) {
        await this.resolveRecursive(resolvedImportPath, undefined, fileMap, visited, depth + 1, remappings, virtualFiles);
      }
    }
  }

  private lookupVirtualFile(posixPath: string, virtualFiles: Map<string, string>): string | undefined {
    if (virtualFiles.has(posixPath)) return virtualFiles.get(posixPath);

    const clean = posixPath.replace(/^\.\//, '');
    if (virtualFiles.has(clean)) return virtualFiles.get(clean);

    // Search by suffix or basename if paths differ in directory prefix
    for (const [key, val] of virtualFiles.entries()) {
      const posixKey = this.toPosix(key);
      if (
        posixKey === clean ||
        posixKey.endsWith(`/${clean}`) ||
        clean.endsWith(`/${posixKey}`) ||
        path.posix.basename(posixKey) === path.posix.basename(clean)
      ) {
        return val;
      }
    }

    return undefined;
  }

  public extractImports(content: string): string[] {
    const importRegex = /import\s+(?:(?:{[^}]+}|[^{};\n]+)\s+from\s+)?["']([^"']+)["']/g;
    const matches: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = importRegex.exec(content)) !== null) {
      matches.push(match[1]);
    }
    return matches;
  }

  public resolveImportPath(
    baseDir: string,
    importPath: string,
    remappings: Record<string, string> = {},
    virtualFiles: Map<string, string> = new Map(),
  ): string | null {
    // 1. Check remappings (e.g., @openzeppelin/ -> lib/openzeppelin-contracts/)
    let mappedPath = importPath;
    for (const [prefix, replacement] of Object.entries(remappings)) {
      if (importPath.startsWith(prefix)) {
        mappedPath = importPath.replace(prefix, replacement);
        break;
      }
    }

    const posixBase = this.toPosix(baseDir);
    const posixMapped = this.toPosix(mappedPath);
    const posixImport = this.toPosix(importPath);

    // 2. Direct virtual lookup
    if (virtualFiles.has(posixMapped)) return posixMapped;
    if (virtualFiles.has(posixImport)) return posixImport;

    // 3. POSIX relative join
    const relativeJoined = path.posix.normalize(path.posix.join(posixBase, posixMapped));
    const cleanJoined = relativeJoined.replace(/^\.\//, '');

    if (virtualFiles.has(relativeJoined)) return relativeJoined;
    if (virtualFiles.has(cleanJoined)) return cleanJoined;

    // Suffix match against virtual files
    for (const key of virtualFiles.keys()) {
      const posixKey = this.toPosix(key);
      if (
        posixKey === cleanJoined ||
        posixKey.endsWith(`/${cleanJoined}`) ||
        cleanJoined.endsWith(`/${posixKey}`) ||
        posixKey.endsWith(`/${posixMapped}`)
      ) {
        return posixKey;
      }
    }

    // 4. Host filesystem fallback for node_modules / lib / foundry
    const candidates = [
      path.resolve(baseDir, mappedPath),
      path.resolve(baseDir, importPath),
      path.resolve(baseDir, 'node_modules', importPath),
      path.resolve(baseDir, 'lib', importPath),
      path.resolve(process.cwd(), 'node_modules', importPath),
      path.resolve(process.cwd(), 'lib', importPath),
    ];

    for (const cand of candidates) {
      if (fs.existsSync(cand)) {
        return this.toPosix(cand);
      }
    }

    return null;
  }
}
