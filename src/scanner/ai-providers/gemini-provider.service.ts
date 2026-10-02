import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { AiProvider, AiScanResult } from './ai-provider.interface';
import { buildSecurityAuditPrompt } from './prompt-builder';

@Injectable()
export class GeminiProviderService implements AiProvider {
  readonly id = 'gemini';
  readonly displayName = 'Google Gemini';
  private readonly logger = new Logger(GeminiProviderService.name);

  isAvailable(): boolean {
    const key = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_API_KEY;
    return !!key && key.trim().length > 0;
  }

  getMissingConfigReason(): string | null {
    if (!this.isAvailable()) {
      return 'Missing GEMINI_API_KEY in environment variables.';
    }
    return null;
  }

  async analyzeContract(
    contractFileName: string,
    code: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    modelOverride?: string,
  ): Promise<AiScanResult> {
    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_API_KEY;
    if (!apiKey) {
      throw new Error('Gemini API key is not configured.');
    }

    const model = modelOverride || process.env.GEMINI_MODEL || 'gemini-2.0-flash';
    const prompt = buildSecurityAuditPrompt(contractFileName, code, staticFindings, protocolContext);

    this.logger.log(`Invoking Google Gemini (${model}) for ${contractFileName}...`);

    const res = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' },
      },
      { timeout: 45000 },
    );

    const jsonText = res.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!jsonText) {
      throw new Error(`Empty response from Gemini API (${model})`);
    }

    const parsed = JSON.parse(jsonText);
    return {
      provider: this.id,
      modelUsed: `Gemini (${model})`,
      contractFileName,
      analysisSummary: parsed.analysisSummary || `Gemini security review completed for ${contractFileName}.`,
      findings: parsed.findings || [],
    };
  }
}
