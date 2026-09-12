import { Injectable, Logger } from '@nestjs/common';
import { ParsedProject, PassFinding } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';
import { Pass01AccessControl } from './pass-01-access-control';
import { Pass02Arithmetic } from './pass-02-arithmetic';
import { Pass03Oracle } from './pass-03-oracle';
import { Pass04ERCCompliance } from './pass-04-erc-compliance';
import { Pass05FrontRunning } from './pass-05-front-running';
import { Pass06Timestamp } from './pass-06-timestamp';
import { Pass07DoS } from './pass-07-dos';
import { Pass08Reentrancy } from './pass-08-reentrancy';
import { Pass09Proxy } from './pass-09-proxy';
import { Pass10TokenRisks } from './pass-10-token-risks';
import { Pass11AssemblyYul } from './pass-11-assembly-yul';
import { Pass12Centralization } from './pass-12-centralization';
import { Pass13InterproceduralTaint } from './pass-13-interprocedural-taint';
import { Pass14SymbolicExecution } from './pass-14-symbolic-execution';

export interface PassRunResult {
  findings: PassFinding[];
  passTimings: Record<string, number>;
}

@Injectable()
export class PassRegistryService {
  private readonly logger = new Logger(PassRegistryService.name);
  private readonly passes: ScannerPass[];

  constructor() {
    this.passes = [
      new Pass01AccessControl(),
      new Pass02Arithmetic(),
      new Pass03Oracle(),
      new Pass04ERCCompliance(),
      new Pass05FrontRunning(),
      new Pass06Timestamp(),
      new Pass07DoS(),
      new Pass08Reentrancy(),
      new Pass09Proxy(),
      new Pass10TokenRisks(),
      new Pass11AssemblyYul(),
      new Pass12Centralization(),
      new Pass13InterproceduralTaint(),
      new Pass14SymbolicExecution(),
    ];
  }

  getPasses(): ScannerPass[] {
    return this.passes;
  }

  async runAllPasses(
    project: ParsedProject,
    config?: PassConfig,
    onPassComplete?: (passNum: number, name: string, findingsCount: number, durationMs: number) => void,
  ): Promise<PassRunResult> {
    const allFindings: PassFinding[] = [];
    const passTimings: Record<string, number> = {};

    for (const pass of this.passes) {
      // Check feature flag if present
      if (config?.featureFlags) {
        const flagName = `FEATURE_PASS_${pass.passNumber.toString().padStart(2, '0')}`;
        if (config.featureFlags[flagName] === false) {
          this.logger.debug(`Skipping Pass ${pass.passNumber} (${pass.name}) due to feature flag`);
          continue;
        }
      }

      const start = Date.now();
      try {
        const passFindings = await pass.run(project, config);
        const durationMs = Date.now() - start;
        passTimings[pass.name] = durationMs;
        allFindings.push(...passFindings);

        if (onPassComplete) {
          onPassComplete(pass.passNumber, pass.name, passFindings.length, durationMs);
        }
      } catch (err: any) {
        const durationMs = Date.now() - start;
        passTimings[pass.name] = durationMs;
        this.logger.error(`Pass ${pass.passNumber} (${pass.name}) failed after ${durationMs}ms: ${err?.message}`);
      }
    }

    return { findings: allFindings, passTimings };
  }
}
