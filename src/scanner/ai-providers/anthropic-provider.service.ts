import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { AiProvider, AiScanResult } from './ai-provider.interface';
import { buildSecurityAuditPrompt } from './prompt-builder';

@Injectable()
export class AnthropicProviderService implements AiProvider {
  readonly id = 'anthropic';
  readonly displayName = 'Anthropic Claude';
  private readonly logger = new Logger(AnthropicProviderService.name);

  isAvailable(): boolean {
    const key = process.env.ANTHROPIC_API_KEY;
    return !!key && key.trim().length > 0;
  }

  getMissingConfigReason(): string | null {
    if (!this.isAvailable()) {
      return 'Missing ANTHROPIC_API_KEY in environment variables.';
    }
    return null;
  }

  async analyzeContract(
    contractFileName: string,
    code: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    modelOverride?: string,
    additionalFiles?: Map<string, string> | Record<string, string>,
  ): Promise<AiScanResult> {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error('Anthropic API key is not configured.');
    }

    const model = modelOverride || process.env.ANTHROPIC_MODEL || 'claude-3-7-sonnet-20250219';
    const rawPrompt = buildSecurityAuditPrompt(
      contractFileName,
      code,
      staticFindings,
      protocolContext,
      additionalFiles,
    );

    this.logger.log(`Invoking Anthropic Claude (${model}) for ${contractFileName}...`);

    const res = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model,
        max_tokens: 4096,
        messages: [
          {
            role: 'user',
            content: `${rawPrompt}\n\nIMPORTANT: Return ONLY the raw JSON object, without backticks, markdown markers, or preliminary text.`,
          },
        ],
      },
      {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        timeout: 60000,
      },
    );

    const rawText = res.data?.content?.[0]?.text;
    if (!rawText) {
      throw new Error(`Empty response from Anthropic API (${model})`);
    }

    // Clean any markdown code blocks if model included them
    const cleaned = rawText.replace(/```json\s*|```\s*/g, '').trim();
    const parsed = JSON.parse(cleaned);

    return {
      provider: this.id,
      modelUsed: `Claude (${model})`,
      contractFileName,
      analysisSummary: parsed.analysisSummary || `Claude security review completed for ${contractFileName}.`,
      findings: parsed.findings || [],
    };
  }
}
