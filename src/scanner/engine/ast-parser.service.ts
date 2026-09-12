import { Injectable, Logger } from '@nestjs/common';
import { parse } from '@solidity-parser/parser';
import type {
  ContractASTSymbol,
  ASTFunctionSymbol,
  ParsedProject,
  ResolvedFile,
  StateVariable,
  InheritanceInfo,
  UsingForDirective,
  ScanDiagnostic,
} from './types';

@Injectable()
export class ASTParserService {
  private readonly logger = new Logger(ASTParserService.name);

  parseProject(fileMap: Map<string, ResolvedFile>): ParsedProject {
    const contracts = new Map<string, ContractASTSymbol>();
    const mergedASTs: any[] = [];
    const diagnostics: ScanDiagnostic[] = [];
    const pragmaVersions = new Map<string, string>();

    for (const [filePath, file] of fileMap.entries()) {
      try {
        const ast = parse(file.content, { loc: true, range: true, tolerant: true });
        mergedASTs.push(ast);
        this.extractContractSymbols(ast, filePath, file.content, contracts, diagnostics);

        const pragmaMatch = file.content.match(/pragma\s+solidity\s+([^;]+);/);
        if (pragmaMatch) {
          pragmaVersions.set(filePath, pragmaMatch[1].trim());
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Failed to parse AST for ${filePath}: ${message}`);
        diagnostics.push({
          code: 'PARSE_ERROR',
          level: 'error',
          message: `Parse error: ${message}`,
          filePath,
        });
      }
    }

    return { files: fileMap, contracts, mergedASTs, diagnostics, pragmaVersions };
  }

  private extractContractSymbols(
    ast: any,
    filePath: string,
    content: string,
    contracts: Map<string, ContractASTSymbol>,
    diagnostics: ScanDiagnostic[],
  ): void {
    if (!ast || ast.type !== 'SourceUnit') return;

    for (const node of ast.children || []) {
      if (node.type !== 'ContractDefinition') continue;

      const functions: ASTFunctionSymbol[] = [];
      const stateVars: StateVariable[] = [];
      const modifiers: any[] = [];
      const events: any[] = [];
      const errors: any[] = [];
      const structs: any[] = [];
      const enums: any[] = [];
      const usingForDirectives: UsingForDirective[] = [];

      for (const subNode of node.subNodes || []) {
        switch (subNode.type) {
          case 'FunctionDefinition':
            functions.push(this.extractFunctionSymbol(subNode));
            break;
          case 'StateVariableDeclaration':
            stateVars.push(...this.extractStateVariables(subNode));
            break;
          case 'ModifierDefinition':
            modifiers.push(subNode);
            break;
          case 'EventDefinition':
            events.push(subNode);
            break;
          case 'CustomErrorDefinition':
            errors.push(subNode);
            break;
          case 'StructDefinition':
            structs.push(subNode);
            break;
          case 'EnumDefinition':
            enums.push(subNode);
            break;
          case 'UsingForDeclaration':
            usingForDirectives.push({
              libraryName: subNode.libraryName || subNode.typeName?.namePath || 'unknown',
              forTypeName: subNode.typeName?.namePath || subNode.typeName?.name || '*',
            });
            break;
        }
      }

      const inheritance = this.extractInheritance(node, usingForDirectives);
      const line = node.loc?.start?.line || 1;

      contracts.set(node.name, {
        name: node.name,
        kind: node.kind || 'contract',
        filePath,
        ast: node,
        functions,
        stateVariables: stateVars,
        modifiers,
        events,
        errors,
        structs,
        enums,
        cfgs: new Map(),
        baseContracts: inheritance.baseContracts,
        linearizedBaseContracts: inheritance.linearization,
        usingForDirectives,
        inheritance,
        line,
      });
    }
  }

  private extractFunctionSymbol(subNode: any): ASTFunctionSymbol {
    const fnName = subNode.name || (subNode.isConstructor ? 'constructor' : subNode.isReceiveEther ? 'receive' : 'fallback');
    const modifiers = (subNode.modifiers || []).map((m: any) => ({
      name: m.name || '',
      arguments: m.arguments || [],
      astNode: m,
    }));
    const parameters = (subNode.parameters || []).map((p: any) => ({
      name: p.name || '',
      typeName: this.resolveTypeName(p.typeName),
    }));
    const returnParameters = (subNode.returnParameters || []).map((p: any) => ({
      name: p.name || '',
      typeName: this.resolveTypeName(p.typeName),
    }));

    return {
      name: fnName,
      visibility: subNode.visibility || 'public',
      stateMutability: subNode.stateMutability || 'default',
      modifiers,
      parameters,
      returnParameters,
      isConstructor: !!subNode.isConstructor,
      isFallback: !subNode.name && !subNode.isConstructor && !subNode.isReceiveEther,
      isReceive: !!subNode.isReceiveEther,
      astNode: subNode,
      line: subNode.loc?.start?.line || 1,
    };
  }

  private extractStateVariables(declaration: any): StateVariable[] {
    const vars: StateVariable[] = [];

    if (declaration.variables) {
      for (const v of declaration.variables) {
        vars.push({
          name: v.name || 'unnamed',
          typeName: this.resolveTypeName(v.typeName),
          visibility: v.visibility || 'default',
          mutability: v.isDeclaredConst ? 'constant' : v.isImmutable ? 'immutable' : 'mutable',
          line: v.loc?.start?.line || declaration.loc?.start?.line || 1,
          astNode: v,
        });
      }
    }

    return vars;
  }

  private resolveTypeName(typeName: any): string {
    if (!typeName) return 'unknown';
    if (typeName.type === 'ElementaryTypeName') return typeName.name || 'unknown';
    if (typeName.type === 'UserDefinedTypeName') return typeName.namePath || 'unknown';
    if (typeName.type === 'Mapping') {
      const key = this.resolveTypeName(typeName.keyType);
      const value = this.resolveTypeName(typeName.valueType);
      return `mapping(${key} => ${value})`;
    }
    if (typeName.type === 'ArrayTypeName') {
      return `${this.resolveTypeName(typeName.baseTypeName)}[]`;
    }
    return 'unknown';
  }

  private extractInheritance(contractNode: any, usingFor: UsingForDirective[]): InheritanceInfo {
    const baseContracts: string[] = [];

    if (contractNode.baseContracts) {
      for (const base of contractNode.baseContracts) {
        const baseName = base.baseName?.namePath || base.baseName?.name;
        if (baseName) baseContracts.push(baseName);
      }
    }

    return {
      baseContracts,
      linearization: [contractNode.name, ...baseContracts],
      usingForDirectives: usingFor,
      isDiamond: baseContracts.length > 1,
    };
  }
}
