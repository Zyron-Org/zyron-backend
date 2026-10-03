import { Injectable, Logger } from '@nestjs/common';
import { ImportResolverService } from '../engine/import-resolver.service';
import { ASTParserService } from '../engine/ast-parser.service';
import { CFGBuilderService } from '../engine/cfg-builder.service';
import { InheritanceResolverService } from '../engine/inheritance-resolver.service';
import { PragmaAnalyzerService } from '../engine/pragma-analyzer.service';
import { PassRegistryService } from '../passes/pass-registry';
import { ScannerGateway } from '../scanner.gateway';
import { PassFinding, ScanDiagnostic } from '../engine/types';
import { PassConfig } from '../passes/pass-interface';

export interface ASTScanExecutionResult {
  findings: PassFinding[];
  diagnostics: ScanDiagnostic[];
  passTimings: Record<string, number>;
  totalDurationMs: number;
}

@Injectable()
export class ASTEngineRunnerService {
  private readonly logger = new Logger(ASTEngineRunnerService.name);

  constructor(
    private importResolver: ImportResolverService,
    private astParser: ASTParserService,
    private cfgBuilder: CFGBuilderService,
    private inheritanceResolver: InheritanceResolverService,
    private pragmaAnalyzer: PragmaAnalyzerService,
    private passRegistry: PassRegistryService,
    private scannerGateway: ScannerGateway,
  ) {}

  async run(
    auditId: string,
    contractFileName: string,
    code: string,
    config?: PassConfig,
    virtualFiles: Map<string, string> = new Map(),
  ): Promise<ASTScanExecutionResult> {
    const startTime = Date.now();
    const diagnostics: ScanDiagnostic[] = [];

    this.logger.log(`[AST Engine] Resolving imports for ${contractFileName} with ${virtualFiles.size} virtual file(s)`);
    const fileMap = await this.importResolver.resolveProject(contractFileName, code, {}, virtualFiles);

    // 1. Analyze Pragma directives
    const pragmaResult = this.pragmaAnalyzer.analyzePragmas(fileMap);
    diagnostics.push(...pragmaResult.diagnostics);

    // 2. Parse AST
    this.logger.log(`[AST Engine] Parsing AST (${fileMap.size} file(s))`);
    const project = this.astParser.parseProject(fileMap);
    diagnostics.push(...project.diagnostics);

    // 3. Resolve Inheritance Chains (C3 Linearization)
    this.logger.log(`[AST Engine] Resolving inheritance & flattened symbols`);
    const inheritanceResult = this.inheritanceResolver.resolveInheritance(project);
    diagnostics.push(...inheritanceResult.diagnostics);

    // 4. Build CFGs with Branching
    this.logger.log(`[AST Engine] Building CFGs for ${project.contracts.size} contract(s)`);
    this.cfgBuilder.buildCFGs(project);

    // 5. Run 14 Analysis Passes
    this.logger.log(`[AST Engine] Running 14 AST analysis passes`);
    const { findings, passTimings } = await this.passRegistry.runAllPasses(
      project,
      config,
      (passNum, name, count, durationMs) => {
        this.emitProgress(auditId, passNum, name, count, durationMs);
      },
    );

    const totalDurationMs = Date.now() - startTime;
    this.logger.log(`[AST Engine] Scan finished in ${totalDurationMs}ms — ${findings.length} finding(s)`);

    return {
      findings,
      diagnostics,
      passTimings,
      totalDurationMs,
    };
  }

  private emitProgress(
    auditId: string,
    passNum: number,
    name: string,
    count: number,
    durationMs: number,
  ): void {
    try {
      this.scannerGateway.emitScanProgress(auditId, {
        passNumber: passNum,
        totalPasses: 14,
        tool: `pass-${String(passNum).padStart(2, '0')}-${name}`,
        log: `[PASS ${passNum}/14] ${name}: ${count} finding(s) (${durationMs}ms)`,
        findingCount: count,
      });
    } catch {
      this.logger.warn(`WebSocket emit failed for pass ${passNum}`);
    }
  }
}
