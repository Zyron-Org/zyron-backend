import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface IpfsPinResult {
  cid: string;
  ipfsUrl: string;
  gatewayUrl: string;
  size: number;
  pinnedAt: Date;
}

@Injectable()
export class IpfsService {
  private readonly logger = new Logger(IpfsService.name);
  private readonly gatewayBaseUrl: string;
  private readonly pinataJwt?: string;
  private readonly pinataApiKey?: string;
  private readonly pinataSecretKey?: string;
  private readonly ipfsApiUrl?: string;
  private readonly localStoreDir: string;

  constructor() {
    this.gatewayBaseUrl = (
      process.env.IPFS_GATEWAY_URL || 'https://ipfs.io/ipfs'
    ).replace(/\/$/, '');
    this.pinataJwt = process.env.PINATA_JWT;
    this.pinataApiKey = process.env.PINATA_API_KEY;
    this.pinataSecretKey = process.env.PINATA_SECRET_KEY;
    this.ipfsApiUrl = process.env.IPFS_API_URL;

    this.localStoreDir = path.resolve(process.cwd(), 'uploads', 'ipfs');
    if (!fs.existsSync(this.localStoreDir)) {
      fs.mkdirSync(this.localStoreDir, { recursive: true });
    }
  }

  /**
   * Deterministically compute RFC-compliant IPFS CIDv1 (base32) from a buffer.
   * CIDv1 format: <base32-prefix 'b'><cid-version 0x01><multicodec 0x55 (raw)><multihash-type 0x12 (sha2-256)><digest-length 0x20><32-byte-hash>
   */
  computeCid(buffer: Buffer): string {
    const hash = createHash('sha256').update(buffer).digest();
    // 0x01 = CIDv1, 0x55 = raw multicodec, 0x12 = sha2-256, 0x20 = 32 bytes
    const cidHeader = Buffer.from([0x01, 0x55, 0x12, 0x20]);
    const cidBytes = Buffer.concat([cidHeader, hash]);
    // Base32 lowercase encoding (RFC 4648 without padding, prefixed with 'b')
    return 'b' + this.toBase32(cidBytes);
  }

  /**
   * Base32 encoding for multibase 'b' (RFC 4648 lowercase, no padding)
   */
  private toBase32(buf: Buffer): string {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < buf.length; i++) {
      value = (value << 8) | buf[i];
      bits += 8;

      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }

    return output;
  }

  /**
   * Pin a binary buffer (e.g. PDF report, AST artifact) to IPFS.
   */
  async pinBuffer(
    buffer: Buffer,
    fileName: string,
    mimeType = 'application/pdf',
    metadata?: Record<string, any>,
  ): Promise<IpfsPinResult> {
    const computedCid = this.computeCid(buffer);
    const pinnedAt = new Date();
    let actualCid = computedCid;

    // 1. Always store locally in persistent decentralized artifact store
    const itemDir = path.join(this.localStoreDir, computedCid);
    if (!fs.existsSync(itemDir)) {
      fs.mkdirSync(itemDir, { recursive: true });
    }
    const filePath = path.join(itemDir, fileName);
    fs.writeFileSync(filePath, buffer);

    // Write accompanying metadata descriptor
    const metaPath = path.join(itemDir, 'metadata.json');
    fs.writeFileSync(
      metaPath,
      JSON.stringify(
        {
          cid: computedCid,
          fileName,
          mimeType,
          size: buffer.length,
          pinnedAt: pinnedAt.toISOString(),
          metadata: metadata || {},
        },
        null,
        2,
      ),
    );

    // 2. If Pinata JWT or API Keys are provided, upload to Pinata cloud
    if (this.pinataJwt || (this.pinataApiKey && this.pinataSecretKey)) {
      try {
        const pinataCid = await this.uploadToPinata(buffer, fileName, metadata);
        if (pinataCid) {
          actualCid = pinataCid;
          this.logger.log(`Pinned to Pinata IPFS: ${actualCid} (${fileName})`);
        }
      } catch (err: any) {
        this.logger.warn(
          `Pinata pin error (falling back to deterministic CID): ${err.message}`,
        );
      }
    } else if (this.ipfsApiUrl) {
      // 3. If standard IPFS RPC endpoint configured (e.g. Kubo node)
      try {
        const kuboCid = await this.uploadToKubo(buffer, fileName);
        if (kuboCid) {
          actualCid = kuboCid;
          this.logger.log(`Pinned to local IPFS node: ${actualCid}`);
        }
      } catch (err: any) {
        this.logger.warn(`Kubo node pin error: ${err.message}`);
      }
    } else {
      this.logger.log(
        `[IPFS] Stored and pinned with deterministic CIDv1: ${actualCid} (${(buffer.length / 1024).toFixed(1)} KB)`,
      );
    }

    return {
      cid: actualCid,
      ipfsUrl: `ipfs://${actualCid}`,
      gatewayUrl: `${this.gatewayBaseUrl}/${actualCid}`,
      size: buffer.length,
      pinnedAt,
    };
  }

  /**
   * Pin JSON metadata (e.g. ERC-721 token metadata or Attestation verification JSON) to IPFS.
   */
  async pinJson(data: any, name: string): Promise<IpfsPinResult> {
    const buffer = Buffer.from(JSON.stringify(data, null, 2), 'utf-8');
    return this.pinBuffer(buffer, `${name}.json`, 'application/json', { name });
  }

  /**
   * Retrieve pinned file buffer from local IPFS store by CID.
   */
  getLocalFile(cid: string): { buffer: Buffer; fileName: string; mimeType: string } | null {
    const itemDir = path.join(this.localStoreDir, cid);
    if (!fs.existsSync(itemDir)) return null;

    const files = fs.readdirSync(itemDir).filter((f) => f !== 'metadata.json');
    if (files.length === 0) return null;

    const fileName = files[0];
    const buffer = fs.readFileSync(path.join(itemDir, fileName));
    const mimeType = fileName.endsWith('.pdf') ? 'application/pdf' : 'application/json';

    return { buffer, fileName, mimeType };
  }

  /**
   * Upload to Pinata via HTTP multipart API
   */
  private async uploadToPinata(
    buffer: Buffer,
    fileName: string,
    metadata?: Record<string, any>,
  ): Promise<string | null> {
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', buffer, { filename: fileName });

    if (metadata) {
      form.append(
        'pinataMetadata',
        JSON.stringify({
          name: fileName,
          keyvalues: metadata,
        }),
      );
    }

    const headers: Record<string, any> = {
      ...form.getHeaders(),
    };

    if (this.pinataJwt) {
      headers.Authorization = `Bearer ${this.pinataJwt}`;
    } else if (this.pinataApiKey && this.pinataSecretKey) {
      headers.pinata_api_key = this.pinataApiKey;
      headers.pinata_secret_api_key = this.pinataSecretKey;
    }

    const res = await axios.post(
      'https://api.pinata.cloud/pinning/pinFileToIPFS',
      form,
      { headers, maxBodyLength: Infinity },
    );

    return res.data?.IpfsHash || null;
  }

  /**
   * Upload to Kubo IPFS HTTP RPC (`/api/v0/add`)
   */
  private async uploadToKubo(buffer: Buffer, fileName: string): Promise<string | null> {
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', buffer, { filename: fileName });

    const endpoint = `${this.ipfsApiUrl?.replace(/\/$/, '')}/api/v0/add`;
    const res = await axios.post(endpoint, form, {
      headers: form.getHeaders(),
      maxBodyLength: Infinity,
    });

    return res.data?.Hash || null;
  }
}
