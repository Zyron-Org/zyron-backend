import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { AiProvider, AiScanResult } from './ai-provider.interface';
import { buildSecurityAuditPrompt } from './prompt-builder';

@Injectable()
export class OpenAiProviderService implements AiProvider {
  readonly id = 'openai';
  readonly displayName = 'OpenAI';
  private readonly logger = new Logger(OpenAiProviderService.name);

  isAvailable(): boolean {
    const key = process.env.OPENAI_API_KEY;
    return !!key && key.trim().length > 0;
  }

  getMissingConfigReason(): string | null {
    if (!this.isAvailable()) {
      return 'Missing OPENAI_API_KEY in environment variables.';
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
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error('OpenAI API key is not configured.');
    }

    const model = modelOverride || process.env.OPENAI_MODEL || 'gpt-4o';
    const prompt = buildSecurityAuditPrompt(contractFileName, code, staticFindings, protocolContext);

    this.logger.log(`Invoking OpenAI (${model}) for ${contractFileName}...`);

    const res = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: 'You are Zyron AI, an institutional smart contract security auditor. Always output valid JSON strictly matching the requested schema.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
      },
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 60000,
      },
    );

    const jsonText = res.data?.choices?.[0]?.message?.content;
    if (!jsonText) {
      throw new Error(`Empty response from OpenAI API (${model})`);
    }

    const parsed = JSON.parse(jsonText);
    return {
      provider: this.id,
      modelUsed: `OpenAI (${model})`,
      contractFileName,
      analysisSummary: parsed.analysisSummary || `OpenAI security review completed for ${contractFileName}.`,
      findings: parsed.findings || [],
    };
  }
}
