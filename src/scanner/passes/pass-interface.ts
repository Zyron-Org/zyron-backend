import { ParsedProject, PassFinding } from '../engine/types';

export interface PassConfig {
  ignoreOpenZeppelin?: boolean;
  solidityVersion?: string;
  featureFlags?: Record<string, boolean>;
}

export interface ScannerPass {
  passNumber: number;
  name: string;
  description: string;
  swcIds: string[];
  cweIds: string[];
  defaultConfidence: string;
  run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]>;
}
