/**
 * The settings, read once at boot. Each has a default, so this machine
 * needs no env file:
 *
 *   KEY_STORE  where the wallet pairs live. `local`, the default: one pair
 *              in keys.json (keys.js). `kms`: the pairs listed in
 *              network/wallet-pairs.json, their private halves in Google
 *              Cloud KMS (pairs.js, kms.js). Any other value is refused at
 *              boot.
 *   PORT       the port to listen on, 3300 by default.
 *   HOST       the address to listen on. Unset: every interface.
 *   MASTERPOD_URL  the masterpod, which is asked before every signature
 *              but a creation's whether the passkey answer that came with
 *              the request is good (masterpod.js; 2026-11-20).
 *              http://localhost:3100 by default; a trailing slash is
 *              dropped.
 *
 * On signer1 and signer2 they are kms, 8300, 127.0.0.1 and
 * https://api.anocloud.com, in the file /etc/signingserver/env, which the
 * unit reads when it exists (deploy/signingserver.service).
 */

/** The key store of this machine and of signing1: one pair in keys.json. */
export const LOCAL = 'local';

/** The key store of signer1 and signer2: the pairs in Google Cloud KMS. */
export const KMS = 'kms';

function keyStore() {
  const value = process.env.KEY_STORE;
  if (value === undefined || value === '') return LOCAL;
  if (value !== LOCAL && value !== KMS) {
    throw new Error(`KEY_STORE must be "${LOCAL}" or "${KMS}", got "${value}"`);
  }
  return value;
}

export const config = Object.freeze({
  keyStore: keyStore(),
  port: Number(process.env.PORT) || 3300,
  host: process.env.HOST || undefined,
  masterpodUrl: (process.env.MASTERPOD_URL || 'http://localhost:3100').replace(/\/+$/, ''),
});
