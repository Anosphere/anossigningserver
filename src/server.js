import { createApp } from './app.js';
import { LOCAL, config } from './config.js';
import { WALLET_PAIRS_FILE, bootCheck, loadPairs } from './pairs.js';

/**
 * Boots the signing server: the settings (config.js); the wallet pairs of
 * the key store (pairs.js loadPairs), the one of keys.json, made on the
 * first boot, or the ones listed in network/wallet-pairs.json; the boot
 * check, in which every pair signs once and the result is verified; then
 * the app on PORT (3300 by default) and HOST (every interface when unset).
 * A boot check that fails ends the process with 1, and nothing listens.
 * Here nothing is logged but the boot lines.
 */
const { keyStore, pairs, created } = await loadPairs(config);
const one = pairs.length === 1;

if (keyStore === LOCAL) {
  console.log(created ? 'keys.json written: a new wallet pair' : 'keys.json loaded');
  console.log(`walletKey            ${pairs[0].walletKey}`);
  console.log(`walletPostQuantumKey ${pairs[0].walletPostQuantumKey}`);
  console.log(`key store ${keyStore}: ${pairs.length} wallet ${one ? 'pair' : 'pairs'}`);
} else {
  console.log(`key store ${keyStore}: ${pairs.length} wallet ${one ? 'pair' : 'pairs'} from ${WALLET_PAIRS_FILE}`);
}

const failed = await bootCheck(pairs);
if (failed) {
  console.error(`boot check failed: pair ${failed.number}: ${failed.reason}`);
  process.exit(1);
}
console.log(`boot check: ${pairs.length} ${one ? 'pair signs and verifies' : 'pairs sign and verify'}`);

const server = createApp(config, pairs).listen(config.port, config.host, () => {
  console.log(`signingserver listening on http://${config.host ?? 'localhost'}:${config.port}`);
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
