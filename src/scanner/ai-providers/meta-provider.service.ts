import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosError } from 'axios';
import { AiProvider, AiScanResult } from './ai-provider.interface';
import { buildSecurityAuditPrompt } from './prompt-builder';

export const DEFAULT_META_BASE_URL = 'https://api.meta.ai/v1';
export const DEFAULT_META_MODEL = 'muse-spark-1.3';

@Injectable()
export class MetaProviderService implements AiProvider {
  readonly id = 'meta';
  readonly displayName = 'Meta AI (Muse Spark)';
  private readonly logger = new Logger(MetaProviderService.name);

  isAvailable(): boolean {
    const key = process.env.MODEL_API_KEY;
    return !!key && key.trim().length > 0;
  }

  getMissingConfigReason(): string | null {
    if (!this.isAvailable()) {
      return 'Missing MODEL_API_KEY in environment variables.';
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
    const apiKey = process.env.MODEL_API_KEY?.trim();
    if (!apiKey) {
      throw new Error('Meta AI API key (MODEL_API_KEY) is not configured.');
    }

    const baseUrl = (process.env.META_API_BASE_URL || DEFAULT_META_BASE_URL).replace(/\/+$/, '');
    if (!baseUrl.startsWith('https://')) {
      throw new Error(`Meta AI baseUrl must use HTTPS (got ${baseUrl}).`);
    }

    const model = (modelOverride || process.env.META_MODEL || DEFAULT_META_MODEL).trim();
    const timeoutMs = Number(process.env.META_TIMEOUT_MS || 45000);
    const maxRetries = Number(process.env.META_MAX_RETRIES || 2);

    const prompt = buildSecurityAuditPrompt(
      contractFileName,
      code,
      staticFindings,
      protocolContext,
      additionalFiles,
    );

    // Standard mode only: never send contributor/data-sharing headers or body parameters.
    const requestBody = {
      model,
      temperature: 0.1,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'You are Zyron AI, an institutional smart contract security auditor powered by Meta AI. Always output valid JSON strictly matching the requested schema.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
    };

    const endpoint = `${baseUrl}/chat/completions`;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const startedAt = Date.now();
      try {
        this.logger.log(
          `Invoking Meta AI (${model}) for ${contractFileName} (attempt ${attempt + 1}/${maxRetries + 1})...`,
        );

        const res = await axios.post(endpoint, requestBody, {
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          timeout: timeoutMs,
        });

        const latencyMs = Date.now() - startedAt;
        const jsonText = res.data?.choices?.[0]?.message?.content;
        if (!jsonText || typeof jsonText !== 'string') {
          throw new Error(`Invalid or empty response from Meta AI API (${model})`);
        }

        const cleaned = jsonText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
        const parsed = JSON.parse(cleaned);
        if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.findings)) {
          throw new Error(`Meta AI response missing findings array (${model})`);
        }

        this.logger.log(
          `Meta AI (${model}) completed review for ${contractFileName} in ${latencyMs}ms (${parsed.findings.length} findings).`,
        );

        return {
          provider: this.id,
          modelUsed: `Meta AI (${res.data?.model || model})`,
          contractFileName,
          analysisSummary:
            parsed.analysisSummary || `Meta AI (${model}) security review completed for ${contractFileName}.`,
          findings: parsed.findings,
        };
      } catch (err: any) {
        const axiosErr = err as AxiosError;
        const status = axiosErr?.response?.status;
        const retryable = status === 429 || (status !== undefined && status >= 500) || axiosErr?.code === 'ECONNABORTED';
        lastError = err instanceof Error ? err : new Error(String(err));

        this.logger.warn(
          `Meta AI request failed (attempt ${attempt + 1}/${maxRetries + 1}, status=${status ?? 'network'}): ${lastError.message}`,
        );

        if (!retryable || attempt === maxRetries) {
          break;
        }
        const retryAfterHeader = axiosErr?.response?.headers?.['retry-after'];
        const retryAfterMs = retryAfterHeader && !Number.isNaN(Number(retryAfterHeader))
          ? Number(retryAfterHeader) * 1000
          : 500 * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, Math.min(retryAfterMs, 5000)));
      }
    }

    throw lastError || new Error(`Meta AI request failed for ${contractFileName}`);
  }
}
