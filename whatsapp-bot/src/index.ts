import { app } from './webhook.js';
import { config } from './config.js';

const PORT = config.port;

app.listen(PORT, () => {
  console.log(`🛡️ ScamShield WhatsApp Security Bot running on port ${PORT}`);
  console.log(`📡 Operating Mode: ${config.mode.toUpperCase()}`);
  console.log(`🔗 Webhook endpoint: http://localhost:${PORT}/webhook`);
  console.log(`💚 Healthcheck endpoint: http://localhost:${PORT}/health`);
});
