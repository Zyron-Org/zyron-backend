import { Injectable, Logger } from '@nestjs/common';
import type { ScanDiagnostic, ResolvedFile } from './types';

@Injectable()
export class PragmaAnalyzerService {
  private readonly logger = new Logger(PragmaAnalyzerService.name);

  /**
   * Alias for analyzeProject for test compatibility.
   */
  analyzePragmas(files: Map<string, ResolvedFile>) {
    return this.analyzeProject(files);
  }

  /**
   * Extract pragma version constraints from all files and detect conflicts.
   */
  analyzeProject(files: Map<string, ResolvedFile>): {
    versions: Map<string, string>;
    diagnostics: ScanDiagnostic[];
    effectiveVersion: string;
  } {
    const versions = new Map<string, string>();
    const diagnostics: ScanDiagnostic[] = [];

    for (const [filePath, file] of files.entries()) {
      const pragma = this.extractPragmaVersion(file.content);
      if (pragma) {
        versions.set(filePath, pragma);
        file.pragmaVersion = pragma;

        if (this.isFloatingPragma(pragma)) {
          diagnostics.push({
            code: 'FLOATING_PRAGMA',
            level: 'warning',
            message: `Floating pragma "${pragma}" — pin to a specific version for reproducible builds`,
            filePath,
            line: this.findPragmaLine(file.content),
          });
        }

        if (this.isOldVersion(pragma)) {
          diagnostics.push({
            code: 'OUTDATED_SOLCONFIG',
            level: 'warning',
            message: `Solidity version "${pragma}" is outdated — consider upgrading to 0.8.x for built-in overflow protection`,
            filePath,
            line: this.findPragmaLine(file.content),
          });
        }
      } else {
        diagnostics.push({
          code: 'MISSING_PRAGMA',
          level: 'warning',
          message: 'No pragma solidity directive found',
          filePath,
        });
      }
    }

    // Detect version conflicts across files
    const uniqueVersions = new Set(versions.values());
    if (uniqueVersions.size > 1) {
      diagnostics.push({
        code: 'VERSION_CONFLICT',
        level: 'warning',
        message: `Multiple Solidity versions detected across files: ${[...uniqueVersions].join(', ')}`,
      });
    }

    const effectiveVersion = this.resolveEffectiveVersion(versions);
    return { versions, diagnostics, effectiveVersion };
  }

  extractPragmaVersion(content: string): string | null {
    const match = content.match(/pragma\s+solidity\s+([^;]+);/);
    return match ? match[1].trim() : null;
  }

  private isFloatingPragma(version: string): boolean {
    return version.startsWith('^') || version.startsWith('>=') || version.includes(' ');
  }

  private isOldVersion(version: string): boolean {
    const numericMatch = version.match(/0\.(\d+)\./);
    if (!numericMatch) return false;
    const minor = parseInt(numericMatch[1], 10);
    return minor < 8;
  }

  hasBuiltinOverflowProtection(version: string): boolean {
    const numericMatch = version.match(/0\.(\d+)\./);
    if (!numericMatch) return true;
    return parseInt(numericMatch[1], 10) >= 8;
  }

  private findPragmaLine(content: string): number {
    const lines = content.split('\n');
    const idx = lines.findIndex((l) => l.includes('pragma solidity'));
    return idx >= 0 ? idx + 1 : 1;
  }

  private resolveEffectiveVersion(versions: Map<string, string>): string {
    if (versions.size === 0) return '0.8.20';

    let highest = '0.0.0';
    for (const v of versions.values()) {
      const numericMatch = v.match(/(\d+\.\d+\.\d+)/);
      if (numericMatch && this.compareVersions(numericMatch[1], highest) > 0) {
        highest = numericMatch[1];
      }
    }
    return highest === '0.0.0' ? '0.8.20' : highest;
  }

  private compareVersions(a: string, b: string): number {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
      if ((pa[i] || 0) > (pb[i] || 0)) return 1;
      if ((pa[i] || 0) < (pb[i] || 0)) return -1;
    }
    return 0;
  }
}
