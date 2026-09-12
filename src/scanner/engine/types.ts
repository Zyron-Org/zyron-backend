import type { ASTNode } from '@solidity-parser/parser/dist/src/ast-types';

// ─── Resolved File ──────────────────────────────────────

export interface ResolvedFile {
  filePath: string;
  content: string;
  imports: string[];
  pragmaVersion?: string;
  lineCount?: number;
}

// ─── State Variable ─────────────────────────────────────

export interface StateVariable {
  name: string;
  typeName: string;
  visibility: 'public' | 'internal' | 'private' | 'default';
  mutability: 'mutable' | 'immutable' | 'constant';
  line: number;
  astNode: ASTNode;
}

// ─── External Call Site ─────────────────────────────────

export interface ExternalCallSite {
  callType: 'call' | 'delegatecall' | 'staticcall' | 'transfer' | 'send';
  targetExpression: string;
  methodName?: string;
  line: number;
  blockId: string;
  isValueTransfer: boolean;
  astNode: ASTNode;
}

// ─── State Mutation Site ────────────────────────────────

export interface StateMutationSite {
  variableName: string;
  line: number;
  blockId: string;
  isMapping: boolean;
  astNode: ASTNode;
}

// ─── CFG Basic Block ────────────────────────────────────

export interface BasicBlock {
  id: string;
  statements: ASTNode[];
  predecessors: string[];
  successors: string[];
  hasExternalCall: boolean;
  hasStateMutation: boolean;
  hasAssembly: boolean;
  isLoopHeader: boolean;
  isConditional: boolean;
  externalCalls: ExternalCallSite[];
  externalCallSites: ExternalCallSite[];
  stateMutations: StateMutationSite[];
  stateMutationSites: StateMutationSite[];
}

// ─── Function Symbol & CFG ──────────────────────────────

export interface ASTFunctionSymbol {
  name: string;
  visibility: 'public' | 'external' | 'internal' | 'private' | 'default';
  stateMutability: 'payable' | 'pure' | 'view' | 'nonpayable' | 'default';
  modifiers: { name: string; arguments?: any[]; astNode?: ASTNode }[];
  parameters: FunctionParameter[];
  returnParameters: FunctionParameter[];
  isConstructor: boolean;
  isFallback: boolean;
  isReceive: boolean;
  astNode: ASTNode;
  line: number;
}

export interface FunctionCFG {
  functionName: string;
  entryBlockId: string;
  exitBlockIds: string[];
  blocks: Map<string, BasicBlock>;
  isPayable: boolean;
  visibility: 'public' | 'external' | 'internal' | 'private' | 'default';
  modifiers: string[];
  parameters: FunctionParameter[];
  returnParameters: FunctionParameter[];
  isConstructor: boolean;
  isFallback: boolean;
  isReceive: boolean;
  line: number;
}

export interface FunctionParameter {
  name: string;
  typeName: string;
  isIndexed?: boolean;
}

// ─── Inheritance ────────────────────────────────────────

export interface InheritanceInfo {
  baseContracts: string[];
  linearization: string[];      // C3 linearized order
  usingForDirectives: UsingForDirective[];
  isDiamond: boolean;
}

export interface UsingForDirective {
  libraryName: string;
  forTypeName: string | '*';
}

// ─── Contract AST Symbol ────────────────────────────────

export interface ContractASTSymbol {
  name: string;
  kind: 'contract' | 'interface' | 'library';
  filePath: string;
  ast: ASTNode;
  functions: ASTFunctionSymbol[];
  stateVariables: StateVariable[];
  modifiers: ASTNode[];
  events: ASTNode[];
  errors: ASTNode[];
  structs: ASTNode[];
  enums: ASTNode[];
  cfgs: Map<string, FunctionCFG>;
  baseContracts?: string[];
  linearizedBaseContracts?: string[];
  usingForDirectives?: UsingForDirective[];
  inheritance: InheritanceInfo;
  line: number;
}

// ─── Parsed Project ─────────────────────────────────────

export interface ParsedProject {
  files: Map<string, ResolvedFile>;
  contracts: Map<string, ContractASTSymbol>;
  mergedASTs: ASTNode[];
  diagnostics: ScanDiagnostic[];
  pragmaVersions: Map<string, string>;
}

// ─── Scan Diagnostic (non-finding) ──────────────────────

export interface ScanDiagnostic {
  code?: string;
  level: 'warning' | 'error' | 'info';
  message: string;
  filePath?: string;
  line?: number;
}

// ─── Taint Analysis ─────────────────────────────────────

export type TaintState =
  | 'UNTAINTED'
  | 'USER_INPUT'       // msg.sender, function parameters
  | 'MSG_VALUE'        // msg.value
  | 'CALLDATA'         // msg.data, raw calldata
  | 'BLOCK_ENV'        // block.timestamp, block.number
  | 'STORAGE_READ'     // Value read from storage
  | 'RETURN_VALUE';    // Return from external call

export interface TaintVariableState {
  variableName: string;
  label: TaintState;
  source: string;
  line: number;
}

// ─── Pass Finding ───────────────────────────────────────

export interface PassFinding {
  ruleId: string;
  swcId: string;
  cweId: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: 'HIGH_CONFIDENCE' | 'MEDIUM_CONFIDENCE' | 'LOW_CONFIDENCE' | 'NEEDS_MANUAL_REVIEW' | 'INFORMATIONAL';
  analysisPass: number;
  filePath: string;
  line: number;
  endLine?: number;
  codeSnippet: string;
  vulnerableCode?: string;
  recommendation?: string;
  remediation?: string;
}

// ─── Pass Config ────────────────────────────────────────

export interface PassConfig {
  ignoreOpenZeppelin?: boolean;
  solidityVersion?: string;
  featureFlags?: Record<string, boolean>;
}
