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
 *
 * On signer1 and signer2 they are kms, 8300 and 127.0.0.1, in the file
 * /etc/signingserver/env, which the unit reads when it exists
 * (deploy/signingserver.service).
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
});
