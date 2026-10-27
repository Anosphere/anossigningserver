import { createApp } from './app.js';
import { loadKeys } from './keys.js';

/**
 * Boots the signing server: the wallet pair from keys.json (made on the
 * first boot), the two public keys logged, then the app on PORT (3300 by
 * default). Nothing else is logged.
 */
const port = Number(process.env.PORT) || 3300;

const keys = loadKeys();
console.log(keys.created ? 'keys.json written: a new wallet pair' : 'keys.json loaded');
console.log(`walletKey            ${keys.publicKeys.walletKey}`);
console.log(`walletPostQuantumKey ${keys.publicKeys.walletPostQuantumKey}`);

const server = createApp(keys).listen(port, () => {
  console.log(`signingserver listening on http://localhost:${port}`);
});

let shuttingDown = false;

/** Stop accepting connections and let in-flight requests finish. */
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${signal} received, shutting down...`);
  setTimeout(() => {
    console.error('Shutdown timed out, forcing exit');
    process.exit(1);
  }, 10_000).unref();
  server.close((err) => process.exit(err ? 1 : 0));
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
