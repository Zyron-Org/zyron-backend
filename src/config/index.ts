import * as dotenv from 'dotenv';

dotenv.config();

export const PORT = parseInt(process.env.PORT || '4000', 10);
export const NODE_ENV = process.env.NODE_ENV || 'development';
export const JWT_SECRET = process.env.JWT_SECRET || 'zyron_secret_jwt_token_key_2026_super_secure';
export const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

export const SWAGGER_USER = process.env.SWAGGER_USER || 'admin';
export const SWAGGER_PASS = process.env.SWAGGER_PASS || 'zyron2026';

export const origins = (process.env.CORS_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000')
  .split(',')
  .map((o) => o.trim());

export const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://zyron:zyron_secret_password@localhost:5432/zyron_db?schema=public';
export const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
export const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10);

export const SMTP_HOST = process.env.SMTP_HOST || '';
export const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
export const SMTP_USER = process.env.SMTP_USER || '';
export const SMTP_PASS = process.env.SMTP_PASS || '';
export const SMTP_FROM = process.env.SMTP_FROM || 'noreply@zyron.security';
export const APP_URL = process.env.APP_URL || 'http://localhost:3000';

export const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
export const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
export const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL || 'http://localhost:4000/api/v1/auth/github/callback';
export const GITHUB_FRONTEND_REDIRECT = process.env.GITHUB_FRONTEND_REDIRECT || 'http://localhost:3000/auth/github/callback';
