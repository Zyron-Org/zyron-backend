import { Injectable, Logger } from '@nestjs/common';
import type { ParsedProject, ScanDiagnostic, ContractASTSymbol } from './types';

@Injectable()
export class InheritanceResolverService {
  private readonly logger = new Logger(InheritanceResolverService.name);

  /**
   * Alias for resolve returning an object with diagnostics.
   */
  resolveInheritance(project: ParsedProject): { diagnostics: ScanDiagnostic[] } {
    const diagnostics = this.resolve(project);
    return { diagnostics };
  }

  /**
   * Resolve inheritance for all contracts in the project.
   * Performs C3 linearization, merges inherited members, and detects diamonds.
   */
  resolve(project: ParsedProject): ScanDiagnostic[] {
    const diagnostics: ScanDiagnostic[] = [];

    for (const [name, contract] of project.contracts.entries()) {
      const bases = contract.baseContracts || contract.inheritance?.baseContracts || [];
      if (bases.length === 0) continue;

      try {
        const linearized = this.c3Linearize(name, project.contracts, new Set());
        contract.linearizedBaseContracts = linearized;
        if (contract.inheritance) {
          contract.inheritance.linearization = linearized;
          contract.inheritance.isDiamond = this.hasDiamond(linearized);
        }

        if (this.hasDiamond(linearized)) {
          diagnostics.push({
            code: 'DIAMOND_INHERITANCE',
            level: 'warning',
            message: `Contract "${name}" has diamond inheritance: ${linearized.join(' → ')}`,
            filePath: contract.filePath,
            line: contract.line,
          });
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        diagnostics.push({
          code: 'LINEARIZATION_ERROR',
          level: 'error',
          message: `C3 linearization failed for "${name}": ${message}`,
          filePath: contract.filePath,
          line: contract.line,
        });
      }

      this.mergeInheritedMembers(contract, project.contracts, diagnostics);
    }

    return diagnostics;
  }

  private c3Linearize(
    contractName: string,
    allContracts: Map<string, ContractASTSymbol>,
    visited: Set<string>,
  ): string[] {
    if (visited.has(contractName)) {
      throw new Error(`Circular inheritance detected involving "${contractName}"`);
    }
    visited.add(contractName);

    const contract = allContracts.get(contractName);
    if (!contract) return [contractName];

    const bases = (contract.baseContracts || []).map((b: any) => typeof b === 'string' ? b : (b as any).name);
    if (bases.length === 0) return [contractName];

    const linearizations: string[][] = [];
    for (const base of bases) {
      const baseLin = this.c3Linearize(base, allContracts, new Set(visited));
      linearizations.push(baseLin);
    }

    linearizations.push([...bases]);

    const result = [contractName];
    const merged = this.c3Merge(linearizations);
    result.push(...merged);

    return result;
  }

  private c3Merge(lists: string[][]): string[] {
    const result: string[] = [];
    const workingLists = lists.map((l) => [...l]);

    while (workingLists.some((l) => l.length > 0)) {
      let found = false;
      for (const list of workingLists) {
        if (list.length === 0) continue;
        const head = list[0];

        const isInTail = workingLists.some((other) => other.indexOf(head) > 0);
        if (!isInTail) {
          result.push(head);
          for (const wl of workingLists) {
            const idx = wl.indexOf(head);
            if (idx >= 0) wl.splice(idx, 1);
          }
          found = true;
          break;
        }
      }

      if (!found) {
        throw new Error('Cannot compute consistent C3 linearization');
      }
    }

    return result;
  }

  private mergeInheritedMembers(
    contract: ContractASTSymbol,
    allContracts: Map<string, ContractASTSymbol>,
    diagnostics: ScanDiagnostic[],
  ): void {
    const ownFunctionNames = new Set(
      contract.functions.map((f: any) => f.name || (f.isConstructor ? 'constructor' : 'fallback')),
    );
    const ownVarNames = new Set(contract.stateVariables.map((v) => v.name));
    const ownModifierNames = new Set(contract.modifiers.map((m: any) => m.name));

    const linearization = contract.linearizedBaseContracts || contract.inheritance?.linearization || [];

    for (const baseName of linearization.slice(1)) {
      const baseContract = allContracts.get(baseName);
      if (!baseContract) continue;

      for (const fn of baseContract.functions) {
        const fnName = (fn as any).name || ((fn as any).isConstructor ? 'constructor' : 'fallback');
        if (!ownFunctionNames.has(fnName)) {
          contract.functions.push(fn);
          ownFunctionNames.add(fnName);
        }
      }

      for (const sv of baseContract.stateVariables) {
        if (!ownVarNames.has(sv.name)) {
          contract.stateVariables.push(sv);
          ownVarNames.add(sv.name);
        } else {
          diagnostics.push({
            code: 'VARIABLE_SHADOWING',
            level: 'warning',
            message: `State variable "${sv.name}" in "${contract.name}" shadows inherited variable from "${baseName}"`,
            filePath: contract.filePath,
            line: contract.line,
          });
        }
      }

      for (const mod of baseContract.modifiers) {
        const modName = (mod as any).name;
        if (modName && !ownModifierNames.has(modName)) {
          contract.modifiers.push(mod);
          ownModifierNames.add(modName);
        }
      }
    }
  }

  private hasDiamond(linearization: string[]): boolean {
    const seen = new Set<string>();
    for (const name of linearization) {
      if (seen.has(name)) return true;
      seen.add(name);
    }
    return false;
  }
}
