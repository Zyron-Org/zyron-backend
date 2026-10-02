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

    const model = modelOverride || process.env.GEMINI_MODEL || 'gemini-3.5-flash-lite';
    const prompt = buildSecurityAuditPrompt(contractFileName, code, staticFindings, protocolContext);

    this.logger.log(`Invoking Google Gemini (${model}) for ${contractFileName}...`);

    let res: any;
    try {
      res = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: 'application/json' },
        },
        { timeout: 45000 },
      );
    } catch (err: any) {
      if ((err.response?.status === 503 || err.response?.status === 404) && model !== 'gemini-3.5-flash-lite') {
        this.logger.warn(`Model ${model} returned ${err.response.status}. Retrying with gemini-3.5-flash-lite...`);
        res = await axios.post(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${apiKey}`,
          {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { responseMimeType: 'application/json' },
          },
          { timeout: 45000 },
        );
      } else {
        throw err;
      }
    }

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
