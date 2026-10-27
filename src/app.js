import express from 'express';
import { signTransaction } from './sign.js';

/**
 * Builds and returns the Express application for a loaded wallet pair
 * (`keys` from keys.js loadKeys). Kept separate from the server so the rig
 * can mount it on a port of its own. No CORS: only the wallet's proxy calls
 * this server. JSON limit 1 MB: a creation is about 60 KB.
 */
export function createApp(keys) {
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));

  app.get('/', (req, res) => {
    res.type('text/plain').send('signingserver');
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
  });

  /** The two public keys, hex: 33 bytes compressed P-256 and 2592 bytes ML-DSA-87. */
  app.get('/public-keys', (req, res) => {
    res.json(keys.publicKeys);
  });

  /** { transaction: { payload, signatures } } in; the same with the two wallet signatures set out. */
  app.post('/sign', (req, res) => {
    const result = signTransaction(req.body, keys.privateKeys);
    if (!result.ok) {
      res.status(400).json({ error: result.reason });
      return;
    }
    res.json({ transaction: result.transaction });
  });

  app.use((req, res) => {
    res.status(404).json({ error: 'Not Found', path: req.originalUrl });
  });

  // Express recognises the error handler by its four parameters. A body that
  // is not JSON lands here as a 400 from express.json.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status ?? 500;
    if (status === 500) console.error(err);
    res.status(status).json({ error: status === 500 ? 'Internal Server Error' : err.message });
  });

  return app;
}
