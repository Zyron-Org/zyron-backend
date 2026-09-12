import { Injectable } from '@nestjs/common';
import type {
  BasicBlock,
  FunctionCFG,
  ParsedProject,
  ExternalCallSite,
  StateMutationSite,
  FunctionParameter,
  ASTFunctionSymbol,
} from './types';

@Injectable()
export class CFGBuilderService {
  private blockCounter = 0;
  buildCFGs(project: ParsedProject): void {
    for (const contract of project.contracts.values()) {
      for (const fnSymbol of contract.functions) {
        const fnAST = (fnSymbol as ASTFunctionSymbol).astNode || fnSymbol;
        const cfg = this.buildFunctionCFG(fnAST as any, contract.name);
        cfg.functionName = fnSymbol.name || cfg.functionName || 'unnamed';
        contract.cfgs.set(cfg.functionName, cfg);
      }
    }
  }

  private buildFunctionCFG(fnAST: any, contractName: string): FunctionCFG {
    this.blockCounter = 0;
    const fnName = fnAST.name || (fnAST.isConstructor ? 'constructor' : fnAST.isReceiveEther ? 'receive' : 'fallback');
    const blocks = new Map<string, BasicBlock>();

    const entryBlock = this.createBlock();
    blocks.set(entryBlock.id, entryBlock);

    const exitBlockIds: string[] = [];

    if (fnAST.body && fnAST.body.statements) {
      const terminalBlocks = this.processStatements(fnAST.body.statements, entryBlock, blocks);
      exitBlockIds.push(...terminalBlocks.map((b) => b.id));
    } else {
      exitBlockIds.push(entryBlock.id);
    }

    const parameters: FunctionParameter[] = (fnAST.parameters || []).map((p: any) => ({
      name: p.name || '',
      typeName: this.resolveTypeName(p.typeName),
    }));

    const returnParameters: FunctionParameter[] = (fnAST.returnParameters || []).map((p: any) => ({
      name: p.name || '',
      typeName: this.resolveTypeName(p.typeName),
    }));

    const modifiers: string[] = (fnAST.modifiers || []).map((m: any) => (typeof m === 'string' ? m : m.name || ''));

    return {
      functionName: fnName,
      entryBlockId: entryBlock.id,
      exitBlockIds,
      blocks,
      isPayable: fnAST.stateMutability === 'payable',
      visibility: fnAST.visibility || 'public',
      modifiers,
      parameters,
      returnParameters,
      isConstructor: !!fnAST.isConstructor,
      isFallback: !fnAST.name && !fnAST.isConstructor && !fnAST.isReceiveEther,
      isReceive: !!fnAST.isReceiveEther,
      line: fnAST.loc?.start?.line || 1,
    };
  }

  private processStatements(statements: any[], currentBlock: BasicBlock, blocks: Map<string, BasicBlock>): BasicBlock[] {
    let active = currentBlock;
    const terminalBlocks: BasicBlock[] = [];

    for (const stmt of statements) {
      if (stmt.type === 'IfStatement') {
        active.statements.push(stmt);
        active.isConditional = true;
        this.analyzeNode(stmt.condition, active);

        const trueBranch = this.createBlock();
        blocks.set(trueBranch.id, trueBranch);
        this.addEdge(active, trueBranch);

        const trueStatements = stmt.trueBody?.statements || (stmt.trueBody ? [stmt.trueBody] : []);
        const trueTerminals = trueStatements.length > 0
          ? this.processStatements(trueStatements, trueBranch, blocks)
          : [trueBranch];

        if (stmt.falseBody) {
          const falseBranch = this.createBlock();
          blocks.set(falseBranch.id, falseBranch);
          this.addEdge(active, falseBranch);

          const falseStatements = stmt.falseBody.statements || (stmt.falseBody.type === 'IfStatement' ? [stmt.falseBody] : []);
          const falseTerminals = falseStatements.length > 0
            ? this.processStatements(falseStatements, falseBranch, blocks)
            : [falseBranch];

          const mergeBlock = this.createBlock();
          blocks.set(mergeBlock.id, mergeBlock);
          for (const t of [...trueTerminals, ...falseTerminals]) {
            this.addEdge(t, mergeBlock);
          }
          active = mergeBlock;
        } else {
          const mergeBlock = this.createBlock();
          blocks.set(mergeBlock.id, mergeBlock);
          this.addEdge(active, mergeBlock);
          for (const t of trueTerminals) {
            this.addEdge(t, mergeBlock);
          }
          active = mergeBlock;
        }
      } else if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement' || stmt.type === 'DoWhileStatement') {
        const loopHeader = this.createBlock();
        loopHeader.isLoopHeader = true;
        blocks.set(loopHeader.id, loopHeader);
        this.addEdge(active, loopHeader);

        if (stmt.conditionExpression || stmt.condition) {
          loopHeader.statements.push(stmt.conditionExpression || stmt.condition);
        }

        const loopBody = this.createBlock();
        blocks.set(loopBody.id, loopBody);
        this.addEdge(loopHeader, loopBody);

        const bodyStatements = stmt.body?.statements || [];
        const bodyTerminals = bodyStatements.length > 0
          ? this.processStatements(bodyStatements, loopBody, blocks)
          : [loopBody];

        for (const t of bodyTerminals) {
          this.addEdge(t, loopHeader);
        }

        const loopExit = this.createBlock();
        blocks.set(loopExit.id, loopExit);
        this.addEdge(loopHeader, loopExit);
        active = loopExit;
      } else if (stmt.type === 'TryStatement') {
        active.statements.push(stmt);

        const tryBody = this.createBlock();
        blocks.set(tryBody.id, tryBody);
        this.addEdge(active, tryBody);

        const tryTerminals = stmt.body?.statements
          ? this.processStatements(stmt.body.statements, tryBody, blocks)
          : [tryBody];

        const allTerminals: BasicBlock[] = [...tryTerminals];

        for (const catchClause of stmt.catchClauses || []) {
          const catchBlock = this.createBlock();
          blocks.set(catchBlock.id, catchBlock);
          this.addEdge(active, catchBlock);

          const catchTerminals = catchClause.body?.statements
            ? this.processStatements(catchClause.body.statements, catchBlock, blocks)
            : [catchBlock];
          allTerminals.push(...catchTerminals);
        }

        const mergeBlock = this.createBlock();
        blocks.set(mergeBlock.id, mergeBlock);
        for (const t of allTerminals) {
          this.addEdge(t, mergeBlock);
        }
        active = mergeBlock;
      } else if (stmt.type === 'ReturnStatement' || stmt.type === 'RevertStatement') {
        active.statements.push(stmt);
        this.analyzeNode(stmt, active);
        terminalBlocks.push(active);
        const deadBlock = this.createBlock();
        blocks.set(deadBlock.id, deadBlock);
        active = deadBlock;
        continue;
      } else if (stmt.type === 'UncheckedStatement') {
        const innerStatements = stmt.body?.statements || [];
        if (innerStatements.length > 0) {
          const innerTerminals = this.processStatements(innerStatements, active, blocks);
          if (innerTerminals.length > 0) {
            active = innerTerminals[innerTerminals.length - 1];
          }
        }
        continue;
      } else {
        active.statements.push(stmt);
        this.analyzeNode(stmt, active);
      }
    }

    if (!terminalBlocks.includes(active)) {
      terminalBlocks.push(active);
    }

    return terminalBlocks;
  }

  private analyzeNode(node: any, block: BasicBlock): void {
    if (!node) return;

    this.walkNode(node, (n: any) => {
      if (n.type === 'FunctionCall') {
        let expr = n.expression;
        if (expr?.type === 'NameValueExpression') {
          expr = expr.expression;
        }

        if (expr?.type === 'MemberAccess') {
          const memberName = expr.memberName;
          if (['call', 'delegatecall', 'staticcall', 'transfer', 'send'].includes(memberName)) {
            const callSite: ExternalCallSite = {
              callType: memberName as ExternalCallSite['callType'],
              targetExpression: this.expressionToString(expr.expression),
              line: n.loc?.start?.line || 1,
              blockId: block.id,
              isValueTransfer: memberName === 'transfer' || memberName === 'send' ||
                (memberName === 'call' && this.hasValueArg(n)),
              astNode: n,
              methodName: memberName,
            };
            block.externalCalls.push(callSite);
            block.externalCallSites.push(callSite);
            block.hasExternalCall = true;
          }
        }
      }

      if (n.type === 'Assignment' || (n.type === 'ExpressionStatement' && n.expression?.type === 'Assignment')) {
        const assignExpr = n.type === 'Assignment' ? n : n.expression;
        const left = assignExpr.left;
        const mutation = this.extractMutationSite(left, n, block);
        if (mutation) {
          block.stateMutations.push(mutation);
          block.stateMutationSites.push(mutation);
          block.hasStateMutation = true;
        }
      } else if (n.type === 'ExpressionStatement' && n.expression?.type === 'BinaryOperation' &&
          ['=', '+=', '-=', '*=', '/=', '|=', '&=', '^=', '<<=', '>>='].includes(n.expression.operator)) {
        const left = n.expression.left;
        const mutation = this.extractMutationSite(left, n, block);
        if (mutation) {
          block.stateMutations.push(mutation);
          block.stateMutationSites.push(mutation);
          block.hasStateMutation = true;
        }
      }

      if (n.type === 'InlineAssemblyStatement' || n.type === 'AssemblyBlock') {
        block.hasAssembly = true;
      }
    });
  }

  private extractMutationSite(left: any, node: any, block: BasicBlock): StateMutationSite | null {
    if (!left) return null;

    if (left.type === 'Identifier') {
      return {
        variableName: left.name,
        line: node.loc?.start?.line || left.loc?.start?.line || 1,
        blockId: block.id,
        isMapping: false,
        astNode: node,
      };
    }

    if (left.type === 'IndexAccess') {
      const baseName = this.expressionToString(left.base);
      return {
        variableName: baseName,
        line: node.loc?.start?.line || left.loc?.start?.line || 1,
        blockId: block.id,
        isMapping: true,
        astNode: node,
      };
    }

    if (left.type === 'MemberAccess') {
      const baseName = this.expressionToString(left);
      return {
        variableName: baseName,
        line: node.loc?.start?.line || left.loc?.start?.line || 1,
        blockId: block.id,
        isMapping: false,
        astNode: node,
      };
    }

    return null;
  }

  private hasValueArg(callNode: any): boolean {
    if (!callNode) return false;
    const raw = JSON.stringify(callNode);
    return raw.includes('"value"');
  }

  private walkNode(node: any, visitor: (n: any) => void): void {
    if (!node || typeof node !== 'object') return;
    visitor(node);

    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && item.type) {
            this.walkNode(item, visitor);
          }
        }
      } else if (child && typeof child === 'object' && child.type) {
        this.walkNode(child, visitor);
      }
    }
  }

  private expressionToString(expr: any): string {
    if (!expr) return 'unknown';
    if (expr.type === 'Identifier') return expr.name;
    if (expr.type === 'MemberAccess') {
      return `${this.expressionToString(expr.expression)}.${expr.memberName}`;
    }
    if (expr.type === 'IndexAccess') {
      return `${this.expressionToString(expr.base)}[...]`;
    }
    if (expr.type === 'FunctionCall') {
      return `${this.expressionToString(expr.expression)}(...)`;
    }
    return 'expr';
  }

  private resolveTypeName(typeName: any): string {
    if (!typeName) return 'unknown';
    if (typeName.type === 'ElementaryTypeName') return typeName.name || 'unknown';
    if (typeName.type === 'UserDefinedTypeName') return typeName.namePath || 'unknown';
    if (typeName.type === 'Mapping') return `mapping(${this.resolveTypeName(typeName.keyType)} => ${this.resolveTypeName(typeName.valueType)})`;
    if (typeName.type === 'ArrayTypeName') return `${this.resolveTypeName(typeName.baseTypeName)}[]`;
    return 'unknown';
  }

  private createBlock(): BasicBlock {
    return {
      id: `block_${this.blockCounter++}`,
      statements: [],
      predecessors: [],
      successors: [],
      hasExternalCall: false,
      hasStateMutation: false,
      hasAssembly: false,
      isLoopHeader: false,
      isConditional: false,
      externalCalls: [],
      externalCallSites: [],
      stateMutations: [],
      stateMutationSites: [],
    };
  }

  private addEdge(from: BasicBlock, to: BasicBlock): void {
    if (!from.successors.includes(to.id)) {
      from.successors.push(to.id);
    }
    if (!to.predecessors.includes(from.id)) {
      to.predecessors.push(from.id);
    }
  }
}
