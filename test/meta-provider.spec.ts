import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import axios from 'axios';
import {
  MetaProviderService,
  AiProviderFactory,
  GeminiProviderService,
  AnthropicProviderService,
  OpenAiProviderService,
  DeepSeekProviderService,
} from '../src/scanner/ai-providers';

vi.mock('axios');

describe('MetaProviderService (Backend AI Triage)', () => {
  const originalEnv = { ...process.env };
  let service: MetaProviderService;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    service = new MetaProviderService();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('reports unavailable when MODEL_API_KEY is missing', () => {
    delete process.env.MODEL_API_KEY;
    expect(service.isAvailable()).toBe(false);
    expect(service.getMissingConfigReason()).toContain('MODEL_API_KEY');
  });

  it('calls https://api.meta.ai/v1/chat/completions with muse-spark-1.3 in Standard mode and parses JSON findings', async () => {
    process.env.MODEL_API_KEY = 'meta-test-secret-key';
    delete process.env.META_API_BASE_URL;
    delete process.env.META_MODEL;

    const mockedPost = vi.mocked(axios.post).mockResolvedValueOnce({
      data: {
        model: 'muse-spark-1.3',
        choices: [
          {
            message: {
              content: JSON.stringify({
                analysisSummary: 'Meta AI identified state reentrancy in withdraw().',
                findings: [
                  {
                    title: 'CRITICAL: Reentrancy in withdraw',
                    severity: 'CRITICAL',
                    cvss: '9.8',
                    taxonomy: 'SWC-107',
                    location: 'VaultCore.sol:42',
                    impact: 'Full drain of ETH',
                    description: 'External call before balance update.',
                    decision: 'CONFIRMED',
                  },
                ],
              }),
            },
          },
        ],
      },
    } as any);

    const res = await service.analyzeContract('VaultCore.sol', 'pragma solidity ^0.8.20; contract VaultCore {}');

    expect(mockedPost).toHaveBeenCalledTimes(1);
    const [url, body, config] = mockedPost.mock.calls[0];
    expect(url).toBe('https://api.meta.ai/v1/chat/completions');
    expect((body as any).model).toBe('muse-spark-1.3');
    // Standard mode only: no contributor flags
    expect(JSON.stringify(body)).not.toContain('contributor');
    expect((config as any).headers.Authorization).toBe('Bearer meta-test-secret-key');
    expect(res.provider).toBe('meta');
    expect(res.modelUsed).toContain('muse-spark-1.3');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].decision).toBe('CONFIRMED');
  });

  it('retries on 429 rate-limit response and succeeds on second attempt', async () => {
    process.env.MODEL_API_KEY = 'meta-test-secret-key';
    const rateLimitErr: any = new Error('Too Many Requests');
    rateLimitErr.response = { status: 429, headers: { 'retry-after': '0' } };

    const mockedPost = vi
      .mocked(axios.post)
      .mockRejectedValueOnce(rateLimitErr)
      .mockResolvedValueOnce({
        data: {
          model: 'muse-spark-1.3',
          choices: [
            {
              message: {
                content: JSON.stringify({
                  analysisSummary: 'Recovered after 429.',
                  findings: [],
                }),
              },
            },
          ],
        },
      } as any);

    const res = await service.analyzeContract('VaultCore.sol', 'contract VaultCore {}');
    expect(mockedPost).toHaveBeenCalledTimes(2);
    expect(res.analysisSummary).toBe('Recovered after 429.');
  });

  it('defaults AiProviderFactory to meta when MODEL_API_KEY is configured', () => {
    process.env.MODEL_API_KEY = 'meta-test-secret-key';
    delete process.env.AI_PROVIDER;

    const factory = new AiProviderFactory(
      new GeminiProviderService(),
      new AnthropicProviderService(),
      new OpenAiProviderService(),
      new DeepSeekProviderService(),
      service,
    );

    const chosen = factory.getProvider();
    expect(chosen.id).toBe('meta');
  });
});
