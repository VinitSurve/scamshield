import dotenv from 'dotenv';
dotenv.config();

export interface WhatsAppConfig {
  mode: 'demo' | 'cloud_api';
  enabled: boolean;
  port: number;
  accessToken: string;
  phoneNumberId: string;
  verifyToken: string;
  appSecret: string;
  scannerApiUrl: string;
  groqApiKeys: string[];
}

export const config: WhatsAppConfig = {
  mode: (process.env.WHATSAPP_MODE === 'cloud_api' ? 'cloud_api' : 'demo') as 'demo' | 'cloud_api',
  enabled: process.env.WHATSAPP_ENABLED !== 'false',
  port: parseInt(process.env.PORT || '3001', 10),
  accessToken: process.env.WHATSAPP_ACCESS_TOKEN || '',
  phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
  verifyToken: process.env.WHATSAPP_VERIFY_TOKEN || 'scamshield_webhook_secret_verify_token_2026',
  appSecret: process.env.WHATSAPP_APP_SECRET || '',
  scannerApiUrl: process.env.SCAMSHIELD_API_URL || 'https://api.scamshield.org',
  groqApiKeys: (process.env.GROQ_API_KEYS || process.env.VITE_DEV_GROQ_KEYS || '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean),
};
