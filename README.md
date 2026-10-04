# ⚡ Zyron Backend — Smart Contract Security API & Orchestration Engine

[![NestJS](https://img.shields.io/badge/NestJS-10.x-red.svg)](https://nestjs.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Prisma ORM](https://img.shields.io/badge/Prisma-6.x-teal.svg)](https://www.prisma.io/)
[![Arbitrum Sepolia](https://img.shields.io/badge/Arbitrum-Sepolia%20421614-28A0F0.svg)](https://sepolia.arbiscan.io/)
[![Swagger Docs](https://img.shields.io/badge/OpenAPI-Swagger%20UI-green.svg)](http://localhost:4000/docs)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**`zyron-backend`** is the core REST API and orchestration engine of the **Zyron Security Platform**. Built with NestJS and Prisma ORM, it powers smart contract audit lifecycle progression, automated AST vulnerability scanning, SIWE (Sign-In with Ethereum) Web3 authentication, GitHub repository integration, autonomous EVM sandbox verification orchestration with `zyron-agent`, and cryptographic EIP-712 on-chain attestation registration on Arbitrum Sepolia.

---

## 📑 Table of Contents

- [Architecture & Responsibilities](#-architecture--responsibilities)
- [Key Features & Modules](#-key-features--modules)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Local Development Setup](#-local-development-setup)
- [Environment Configuration](#-environment-configuration)
- [Database Management](#-database-management)
- [Deployment Guide](#-deployment-guide)
  - [1. PM2 Process Manager (Recommended for Single Servers)](#1-pm2-process-manager)
  - [2. Systemd Service (Linux Bare-Metal / VPS)](#2-systemd-service)
  - [3. Docker Container Deployment](#3-docker-container-deployment)
  - [4. Production Cloud / Kubernetes](#4-production-cloud--kubernetes)
- [API & Swagger OpenAPI Documentation](#-api--swagger-openapi-documentation)
- [Testing & Quality Assurance](#-testing--quality-assurance)

---

## 🏛️ Architecture & Responsibilities

`zyron-backend` acts as the central hub of the Zyron ecosystem, coordinating clients, human lead auditors, automated scanners, autonomous EVM agents, and the Arbitrum Sepolia blockchain:

```
                          ┌────────────────────────┐
                          │     zyron-frontend     │
                          │   (Next.js App Router) │
                          └───────────┬────────────┘
                                      │ REST API / WebSocket
                                      ▼
                       ┌──────────────────────────────┐
                       │        zyron-backend         │
                       │   (NestJS API on Port 4000)  │
                       └──────────────┬───────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
 ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
 │     SQLite / PG      │  │     zyron-agent      │  │   Arbitrum Sepolia   │
 │     Prisma ORM       │  │ (Port 5001 Microsvc) │  │  ZyronAttestation.sol│
 │  (Audits & Findings) │  │ (Sandbox EVM Prover) │  │ (0x7682... On-Chain) │
 └──────────────────────┘  └──────────────────────┘  └──────────────────────┘
```

---

## ✨ Key Features & Modules

- **Authentication & Web3 SIWE (`/api/v1/auth`)**:
  - Sign-In with Ethereum (EIP-4361 SIWE) with nonce verification.
  - Traditional JWT email/password with verification workflows.
  - GitHub OAuth integration for automated repository syncing.
- **Audit Engagements (`/api/v1/audits`)**:
  - 4-stage deterministic lifecycle: `PENDING` $\to$ `SCANNING` $\to$ `IN_REVIEW` $\to$ `CORRECTIONS_REQUESTED` $\to$ `COMPLETED`.
  - Automatic load-balanced lead auditor assignment.
  - Remediation passes and fix-commit re-verifications.
- **Vulnerability Findings (`/api/v1/findings`)**:
  - SWC / CWE taxonomy classification, CVSS severity ratings, and line-level code references.
  - Per-finding remediation comment threads with commit tracking.
  - False-positive dismissal justifications.
- **Autonomous Prover Bridge (`/api/v1/scanner`)**:
  - Triggers deep EVM sandbox replays via `zyron-agent`.
  - Ingests HMAC-authenticated callbacks with step-by-step trace steps and synthesized Foundry PoCs.
- **Cryptographic On-Chain Attestation (`/api/v1/audits/:id/attestation`)**:
  - Generates EIP-712 structured typed payloads containing the Merkle root of resolved findings, contract bytecode hash, and audit metadata.
  - Directly verifiable on Arbitrum Sepolia (`ZyronAttestation.sol` at `0x7682b6ddc20ce79b1cc4c30647f0384e7f2ab918`).
- **Document Vault & Reports (`/api/v1/reports`, `/api/v1/audits/:id/ipfs`)**:
  - Server-side PDF report synthesis and SHA-256 integrity hash calculation.
  - IPFS metadata manifest pinning for decentralized archiving.
- **Free Public Beta Access Model (`/api/v1/payments/model`)**:
  - Platform operating on a 100% complimentary public beta model.

---

## 📂 Repository Structure

```
zyron-backend/
├── prisma/
│   ├── schema.prisma               # Prisma data models (AuditRequest, Finding, User, etc.)
│   └── seed.ts                     # Database seed data for testing
├── src/
│   ├── audit/                      # Audit engagement workflows & controllers
│   ├── auth/                       # SIWE, JWT, and GitHub OAuth authentication
│   ├── blockchain/                 # Chain configurations & EIP-712 attestation service
│   │   ├── services/
│   │   │   ├── attestation.service.ts
│   │   │   ├── chain-config.service.ts
│   │   │   └── transaction-verifier.service.ts
│   ├── common/                     # Guards, decorators, filters, and interceptors
│   ├── database/                   # Prisma database module
│   ├── integrations/               # GitHub repository parser & file content services
│   ├── ipfs/                       # IPFS pinning & report gateway service
│   ├── payment/                    # Access model & corporate invoice controller
│   ├── scanner/                    # Slither/Mythril engine & zyron-agent orchestrator
│   ├── storage/                    # S3 / local file storage service
│   ├── users/                      # User administration & role management
│   ├── app.module.ts               # Root NestJS application module
│   ├── config.ts                   # Environment configuration exports
│   └── main.ts                     # Application bootstrap & Swagger initialization
├── .env.example                    # Environment variable template
├── package.json                    # Dependencies & npm scripts
└── tsconfig.json                   # TypeScript compiler configuration
```

---

## 📋 Prerequisites

| Requirement | Minimum Version | Recommended | Notes |
| :--- | :--- | :--- | :--- |
| **Node.js** | `>= 20.0.0` | `22.x LTS` | Runtime |
| **npm** | `>= 9.0.0` | `10.x` | Package manager |
| **Database** | SQLite (Dev) / PostgreSQL (Prod) | PostgreSQL 16 | Supported by Prisma |
| **Google Gemini API Key** | N/A | Active Key | Used by automated scanner |

---

## 🚀 Local Development Setup

### 1. Install Dependencies

```bash
cd zyron-backend
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Ensure `DATABASE_URL`, `JWT_SECRET`, and `GEMINI_API_KEY` are configured.

### 3. Initialize Database & Prisma

Generate Prisma Client and push schema to your local database:

```bash
npx prisma generate
npx prisma db push
```

*(Optional) Seed initial demo records and findings:*
```bash
npm run seed
```

### 4. Start Development Server

```bash
npm run start:dev
```

The API server will listen on `http://localhost:4000/api/v1`.  
Interactive Swagger docs are accessible at **`http://localhost:4000/docs`** (Credentials: `admin` / `zyron2026`).

---

## ⚙️ Environment Configuration

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `PORT` | No | `4000` | HTTP port for the NestJS API |
| `NODE_ENV` | No | `development` | Runtime environment (`development`, `production`, `test`) |
| `DATABASE_URL` | **Yes** | `"file:./dev.db"` | Prisma database connection string |
| `JWT_SECRET` | **Yes** | — | Cryptographic secret for signing session tokens |
| `JWT_EXPIRES_IN` | No | `24h` | JWT validity duration |
| `SWAGGER_USER` | No | `admin` | HTTP Basic Auth username for Swagger `/docs` |
| `SWAGGER_PASS` | No | `zyron2026` | HTTP Basic Auth password for Swagger `/docs` |
| `CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:3001` | Allowed CORS origins (comma-separated) |
| `GEMINI_API_KEY` | **Yes** | — | Google Gemini API key for automated scanning |
| `GEMINI_MODEL` | No | `gemini-3.5-flash` | Gemini model for static scan assistance |
| `ATTESTATION_CONTRACT_ADDRESS` | **Yes** | `0x7682...` | Deployed `ZyronAttestation.sol` contract address |
| `DEFAULT_ATTESTATION_CHAIN_ID` | No | `421614` | Default chain ID (Arbitrum Sepolia = 421614) |
| `OPERATOR_PRIVATE_KEY` | No | `""` | Optional relayer wallet key for backend gas sponsorship |
| `ZYRON_AGENT_URL` | No | `http://localhost:5001` | Base URL of the `zyron-agent` prover microservice |
| `AGENT_API_KEY` | **Yes** | — | Shared key for authenticating with `zyron-agent` |
| `CALLBACK_SHARED_SECRET` | **Yes** | — | HMAC secret for verifying incoming agent callbacks |
| `GITHUB_CLIENT_ID` | No | — | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth app client secret |

---

## 🗄️ Database Management

`zyron-backend` uses **Prisma ORM** for database migrations, model schemas, and type generation.

```bash
# Push schema updates directly to the database
npx prisma db push

# Create and apply a migration (production workflows)
npx prisma migrate dev --name <migration_name>

# Open Prisma Studio web inspector
npx prisma studio

# Re-generate the TypeScript Prisma Client
npx prisma generate
```

---

## 🚢 Deployment Guide

### 1. PM2 Process Manager

1. **Build the production bundle**:
   ```bash
   npm run build
   ```

2. **Run database migrations**:
   ```bash
   npx prisma migrate deploy
   ```

3. **Create `ecosystem.config.js` in `zyron-backend/`**:
   ```javascript
   module.exports = {
     apps: [
       {
         name: "zyron-backend",
         script: "dist/main.js",
         instances: "max",
         exec_mode: "cluster",
         autorestart: true,
         watch: false,
         max_memory_restart: "1G",
         env: {
           NODE_ENV: "production",
           PORT: 4000,
         },
       },
     ],
   };
   ```

4. **Start and persist with PM2**:
   ```bash
   pm2 start ecosystem.config.js
   pm2 save
   pm2 startup
   ```

---

### 2. Systemd Service

For Ubuntu / Debian production hosts:

1. **Create `/etc/systemd/system/zyron-backend.service`**:
   ```ini
   [Unit]
   Description=Zyron Protocol API Backend
   After=network.target

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/var/www/zyron/zyron-backend
   ExecStart=/usr/bin/node dist/main.js
   Restart=always
   RestartSec=5
   Environment=NODE_ENV=production
   EnvironmentFile=/var/www/zyron/zyron-backend/.env
   StandardOutput=append:/var/log/zyron-backend.log
   StandardError=append:/var/log/zyron-backend-error.log

   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable zyron-backend
   sudo systemctl start zyron-backend
   sudo systemctl status zyron-backend
   ```

---

### 3. Docker Container Deployment

```dockerfile
FROM node:22-bullseye-slim AS builder
WORKDIR /app
COPY package*.json prisma ./
RUN npm ci
COPY . .
RUN npx prisma generate
RUN npm run build

FROM node:22-bullseye-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --only=production
COPY prisma ./prisma
RUN npx prisma generate
COPY --from=builder /app/dist ./dist

EXPOSE 4000
CMD ["node", "dist/main.js"]
```

---

### 4. Production Cloud / Kubernetes

- **Health Probe**: Use `GET /api/v1/payments/model` or `GET /docs` for liveness and readiness checks.
- **Stateless Clustering**: In cluster mode, multiple replicas can run behind any reverse proxy (Nginx, Traefik, AWS ALB) when connected to a shared PostgreSQL instance.

---

## 📡 API & Swagger OpenAPI Documentation

Interactive Swagger documentation is served directly from the application at:
👉 **`http://localhost:4000/docs`**

### Key Endpoint Groups:
- **`GET /api/v1/auth/siwe/nonce` & `POST /api/v1/auth/siwe/verify`**: Web3 wallet authentication.
- **`POST /api/v1/audits` & `GET /api/v1/audits`**: Audit intake and engagement listing.
- **`GET /api/v1/audits/:id/attestation/payload`**: Returns structured EIP-712 payload for auditor signing.
- **`POST /api/v1/audits/:id/attestation/sign`**: Finalizes report, saves on-chain tx hash, and seals engagement.
- **`POST /api/v1/scanner/audits/:id/prove`**: Dispatches vulnerability proof request to `zyron-agent`.
- **`GET /api/v1/payments/model`**: Returns active complimentary public beta status.

---

## 🧪 Testing & Quality Assurance

```bash
# Run unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Run end-to-end API tests
npm run test:e2e

# Run linter
npm run lint
```

---

## 📄 License

This repository is open-source software licensed under the **[MIT License](LICENSE)**.
