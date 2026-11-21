import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Search and load environment variables from candidate paths
const envCandidates = [
  path.resolve(process.cwd(), '.env'),
  path.resolve(__dirname, '../.env'),
  path.resolve(__dirname, '../../extension/.env'),
  path.resolve(__dirname, '../../.env'),
];

for (const envPath of envCandidates) {
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
  }
}

export interface WhatsAppConfig {
  mode: 'demo' | 'mock' | 'cloud_api';
  enabled: boolean;
  port: number;
  accessToken: string;
  phoneNumberId: string;
  verifyToken: string;
  appSecret: string;
  scannerApiUrl: string;
  geminiApiKeys: string[];
  groqApiKeys: string[];
}

const parseKeys = (keysString?: string): string[] => {
  if (!keysString) return [];
  return keysString
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);
};

const resolveMode = (envMode?: string): 'demo' | 'mock' | 'cloud_api' => {
  if (envMode === 'cloud_api') return 'cloud_api';
  if (envMode === 'mock') return 'mock';
  return 'demo';
};

export const config: WhatsAppConfig = {
  mode: resolveMode(process.env.WHATSAPP_MODE),
  enabled: process.env.WHATSAPP_ENABLED !== 'false',
  port: parseInt(process.env.PORT || '3001', 10),
  accessToken: process.env.WHATSAPP_ACCESS_TOKEN || '',
  phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
  verifyToken: process.env.WHATSAPP_VERIFY_TOKEN || 'scamshield_webhook_secret_verify_token_2026',
  appSecret: process.env.WHATSAPP_APP_SECRET || '',
  scannerApiUrl: process.env.SCAMSHIELD_API_URL || 'https://api.scamshield.org',
  geminiApiKeys: parseKeys(
    process.env.GEMINI_API_KEYS ||
      process.env.VITE_DEV_GEMINI_KEYS ||
      process.env.GEMINI_API_KEY ||
      process.env.GOOGLE_API_KEY
  ),
  groqApiKeys: parseKeys(
    process.env.GROQ_API_KEYS ||
      process.env.VITE_DEV_GROQ_KEYS ||
      process.env.GROQ_API_KEY
  ),
};
