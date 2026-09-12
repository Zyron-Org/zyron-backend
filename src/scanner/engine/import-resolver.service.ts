import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { ResolvedFile } from './types';

@Injectable()
export class ImportResolverService {
  private readonly logger = new Logger(ImportResolverService.name);

  /**
   * Resolves a project starting from entry file path or virtual files map.
   */
  async resolveProject(
    entryFilePath: string,
    rawContent?: string,
    remappings: Record<string, string> = {},
    virtualFiles: Map<string, string> = new Map(),
  ): Promise<Map<string, ResolvedFile>> {
    const fileMap = new Map<string, ResolvedFile>();
    const visited = new Set<string>();
    await this.resolveRecursive(entryFilePath, rawContent, fileMap, visited, 0, remappings, virtualFiles);
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
    const normalizedPath = path.normalize(filePath);
    if (visited.has(normalizedPath)) return;
    visited.add(normalizedPath);

    if (depth > 50) {
      this.logger.warn(`Import depth limit (50) exceeded at ${normalizedPath}. Stopping branch.`);
      return;
    }

    let content = rawContent ?? virtualFiles.get(normalizedPath) ?? virtualFiles.get(filePath);
    if (content === undefined && fs.existsSync(normalizedPath)) {
      try {
        content = fs.readFileSync(normalizedPath, 'utf-8');
      } catch (err: any) {
        this.logger.error(`Failed to read file ${normalizedPath}: ${err.message}`);
      }
    }

    if (!content) {
      this.logger.debug(`No content found for file: ${normalizedPath}`);
      return;
    }

    const imports = this.extractImports(content);
    fileMap.set(normalizedPath, { filePath: normalizedPath, content, imports });

    const baseDir = path.dirname(normalizedPath);
    for (const imp of imports) {
      const resolvedImportPath = this.resolveImportPath(baseDir, imp, remappings, virtualFiles);
      if (resolvedImportPath) {
        await this.resolveRecursive(resolvedImportPath, undefined, fileMap, visited, depth + 1, remappings, virtualFiles);
      }
    }
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

    // Direct virtual match
    if (virtualFiles.has(mappedPath)) return mappedPath;
    if (virtualFiles.has(importPath)) return importPath;

    const candidates = [
      path.resolve(baseDir, mappedPath),
      path.resolve(baseDir, importPath),
      path.resolve(baseDir, 'node_modules', importPath),
      path.resolve(baseDir, 'lib', importPath),
      path.resolve(process.cwd(), 'node_modules', importPath),
      path.resolve(process.cwd(), 'lib', importPath),
    ];

    for (const cand of candidates) {
      const normCand = path.normalize(cand);
      if (virtualFiles.has(normCand) || fs.existsSync(normCand)) {
        return normCand;
      }
    }

    return null;
  }
}
