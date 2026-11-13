import express from 'express';
import { randomPair } from './pairs.js';
import { signRequest } from './sign.js';

/**
 * Builds and returns the Express application for the settings (`config`
 * of config.js) and the loaded wallet pairs (`pairs` of pairs.js
 * loadPairs). Kept separate from the server so the rig
 * can mount it on a port of its own. No CORS: only the wallet's proxy calls
 * this server. JSON limit 1 MB: a creation is about 60 KB.
 *
 * One line is logged per signature and one per refusal. The kind is one of
 * the 16 names of checks/kinds.js and the signer is hex this server made,
 * so no line carries text the sender chose; no payload and no signature is
 * ever logged.
 */
export function createApp(config, pairs) {
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));

  app.get('/', (req, res) => {
    res.type('text/plain').send('signingserver');
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), keyStore: config.keyStore, pairs: pairs.length });
  });

  /**
   * The two public keys of one pair, picked at random, hex: 33 bytes
   * compressed P-256 and 2592 bytes ML-DSA-87. The wallet asks for every
   * new account and puts them into its creation.
   */
  app.get('/public-keys', (req, res) => {
    const { walletKey, walletPostQuantumKey } = randomPair(pairs);
    res.json({ walletKey, walletPostQuantumKey });
  });

  /**
   * { transaction: { payload, signatures }, creation: { payload } } in; the
   * transaction with the two wallet signatures set out, once the checks of
   * sign.js passed. 400 with the reason when one fails; 503 when the pair
   * could not sign.
   */
  app.post('/sign', async (req, res) => {
    const result = await signRequest(req.body, pairs);
    if (result.ok) {
      console.log(`signed ${result.kind} for ${result.signer} with pair ${result.pair}`);
      res.json({ transaction: result.transaction });
      return;
    }
    console.log(result.status === 503 ? `${result.reason}: ${result.detail}` : `refused: ${result.reason}`);
    res.status(result.status).json({ error: result.reason });
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
