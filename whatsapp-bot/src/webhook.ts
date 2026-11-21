import express, { Request, Response } from 'express';
import { config } from './config.js';
import { ScannerClient } from './scanner-client.js';
import { BotSecurity } from './security.js';
import { BackendAIEngine } from './ai-engine.js';

export const app = express();
app.use(express.json());

// Enable CORS for Browser Extension local communication
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Client-App, X-Client-Version');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Set of processed message IDs to prevent duplicate webhook delivery execution
const processedMessageIds = new Set<string>();

/**
 * Health check endpoint
 */
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'scamshield-whatsapp-bot',
    mode: config.mode,
    enabled: config.enabled,
    geminiKeysConfigured: config.geminiApiKeys.length,
    groqKeysConfigured: config.groqApiKeys.length,
    timestamp: new Date().toISOString(),
  });
});

/**
 * Backend Message Threat Analysis Endpoint (POST /api/v1/analyze/message)
 * Executes Multi-Provider AI (Gemini + Groq fallback) with local heuristic backup
 */
app.post('/api/v1/analyze/message', async (req: Request, res: Response) => {
  try {
    const { messageText, sourceType, userLanguage } = req.body;
    if (!messageText || typeof messageText !== 'string') {
      res.status(400).json({ error: 'Missing or invalid messageText in request body' });
      return;
    }

    const result = await BackendAIEngine.analyzeMessage(
      messageText,
      sourceType || 'SMS',
      userLanguage || 'en'
    );

    res.json(result);
  } catch (err: any) {
    res.status(500).json({
      error: err.message || 'Message analysis failed on backend',
      success: false,
    });
  }
});

/**
 * Backend Vision OCR Endpoint (POST /api/v1/analyze/image-vision)
 * Securely uses server-configured Groq API keys without exposing secrets to client
 */
app.post('/api/v1/analyze/image-vision', async (req: Request, res: Response) => {
  try {
    const { imageDataUrl, prompt } = req.body;
    if (!imageDataUrl) {
      res.status(400).json({ error: 'Missing imageDataUrl in request payload' });
      return;
    }

    const groqKey = config.groqApiKeys[0];
    if (!groqKey) {
      res.status(503).json({ error: 'No Groq API keys configured on backend' });
      return;
    }

    const visionPrompt =
      prompt ||
      'Extract all readable text, URLs, phone numbers, and sender info from this image. Transcribe every word accurately.';

    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${groqKey}`,
        'User-Agent': 'ScamShield-Backend/1.0',
      },
      body: JSON.stringify({
        model: 'qwen/qwen3.8-27b',
        messages: [
          {
            role: 'system',
            content:
              'You are ScamShield AI Vision OCR engine. Transcribe all text, messages, URLs, links, and phone numbers from the provided image accurately.',
          },
          {
            role: 'user',
            content: [
              { type: 'text', text: visionPrompt },
              { type: 'image_url', image_url: { url: imageDataUrl } },
            ],
          },
        ],
        temperature: 0.1,
        max_tokens: 1024,
      }),
    });

    if (!groqRes.ok) {
      const err = await groqRes.text();
      res.status(groqRes.status).json({ error: `Groq Vision request failed: ${err}` });
      return;
    }

    const data = await groqRes.json();
    const content = data?.choices?.[0]?.message?.content || '';

    res.json({
      success: true,
      provider: 'groq',
      model: 'qwen/qwen3.8-27b',
      extractedText: content,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Vision analysis failed' });
  }
});

/**
 * Meta Webhook Verification (GET /webhook)
 */
app.get('/webhook', (req: Request, res: Response) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === config.verifyToken) {
    console.log('[ScamShield WhatsApp] Webhook verified successfully by Meta challenge.');
    res.status(200).send(challenge);
  } else {
    console.warn('[ScamShield WhatsApp] Webhook verification failed. Invalid verify token.');
    res.status(403).json({ error: 'Verification token mismatch' });
  }
});

/**
 * Meta Webhook Message Receiver (POST /webhook)
 */
app.post('/webhook', async (req: Request, res: Response) => {
  try {
    const body = req.body;

    if (body.object !== 'whatsapp_business_account') {
      res.status(404).json({ error: 'Invalid object type' });
      return;
    }

    const entries = body.entry || [];
    for (const entry of entries) {
      const changes = entry.changes || [];
      for (const change of changes) {
        const value = change.value;
        const messages = value?.messages || [];

        for (const msg of messages) {
          const messageId = msg.id;

          // Prevent duplicate execution on retried webhooks
          if (processedMessageIds.has(messageId)) {
            console.log(`[ScamShield WhatsApp] Skipping already processed message ID: ${messageId}`);
            continue;
          }
          processedMessageIds.add(messageId);

          const sender = msg.from;
          const msgType = msg.type;

          console.log(`[ScamShield WhatsApp] Received ${msgType} message from ${sender}`);

          if (msgType === 'text') {
            const userText = msg.text?.body || '';
            const scanResult = await ScannerClient.scanMessage(userText);

            // In demo mode, log the formatted reply
            console.log(`[ScamShield WhatsApp] Generated Reply for ${sender}:\n`, scanResult.formattedReply);

            // In cloud_api mode with access token, send WhatsApp reply via Meta Graph API
            if (config.mode === 'cloud_api' && config.accessToken && config.phoneNumberId) {
              await sendWhatsAppMessage(sender, scanResult.formattedReply);
            }
          } else if (msgType === 'image') {
            const mediaUrl = msg.image?.url;
            if (mediaUrl) {
              const isSafe = BotSecurity.isSafeMediaUrl(mediaUrl);
              if (!isSafe) {
                console.warn('[ScamShield WhatsApp] Blocked unsafe media URL (SSRF protection):', mediaUrl);
                continue;
              }
            }

            const scanResult = await ScannerClient.scanMessage('Image received: scanning for KYC and payment threats.');
            console.log(`[ScamShield WhatsApp] Generated Image Reply for ${sender}:\n`, scanResult.formattedReply);
          }
        }
      }
    }

    res.status(200).json({ status: 'EVENT_RECEIVED' });
  } catch (err: any) {
    console.error('[ScamShield WhatsApp] Error handling webhook payload:', err);
    res.status(500).json({ error: 'Internal processing error' });
  }
});

/**
 * Sends a message back to the user using Meta WhatsApp Cloud API
 */
async function sendWhatsAppMessage(recipientPhone: string, messageText: string): Promise<void> {
  const url = `https://graph.facebook.com/v21.0/${config.phoneNumberId}/messages`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: recipientPhone,
        type: 'text',
        text: { body: messageText },
      }),
    });

    if (!response.ok) {
      console.error(`[ScamShield WhatsApp] Meta API error: ${response.status} ${await response.text()}`);
    } else {
      console.log(`[ScamShield WhatsApp] Message delivered successfully to ${recipientPhone}`);
    }
  } catch (err) {
    console.error('[ScamShield WhatsApp] Network error sending WhatsApp reply:', err);
  }
}
