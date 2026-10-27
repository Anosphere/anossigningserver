import { createPrivateKey, createPublicKey, generateKeyPairSync, ECDH } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ECDSA_P256, ML_DSA_87 } from './crypto/signatures.js';

/**
 * The wallet pair: a P-256 key and an ML-DSA-87 key, the walletKey and
 * walletPostQuantumKey of every account a wallet creates and the pair that
 * co-signs every transfer (spec section 3). Kept in keys.json in the project
 * root, git-ignored, made at first boot when the file is missing.
 *
 * In the file: private keys as PKCS#8 DER in hex; public keys raw, the SPKI
 * prefix cut, as keyholdersoftware's make-keys does: the P-256 key as its
 * 33-byte compressed point, the ML-DSA-87 key as its 2592 bytes. Those raw
 * public keys are what /public-keys answers and what a creation payload
 * carries.
 */

const KEYS_FILE = fileURLToPath(new URL('../keys.json', import.meta.url));

/** The two roles of the wallet pair, as a creation payload and a signatures object name them. */
export const WALLET_KEY = 'walletKey';
export const WALLET_POST_QUANTUM_KEY = 'walletPostQuantumKey';

/** The SPKI DER prefix lengths and raw public key sizes, as make-keys has them. */
const SPKI_PREFIX_BYTES = { p256: 26, 'ml-dsa-87': 22 };
const RAW_PUBLIC_BYTES = { p256: 65, 'ml-dsa-87': 2592 };

const hex = (bytes) => Buffer.from(bytes).toString('hex');

function pkcs8Hex(privateKey) {
  return hex(privateKey.export({ format: 'der', type: 'pkcs8' }));
}

/** The raw public key out of a KeyObject: its SPKI DER with the fixed prefix cut. */
function rawPublic(publicKey, algorithm) {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const expected = SPKI_PREFIX_BYTES[algorithm] + RAW_PUBLIC_BYTES[algorithm];
  if (spki.length !== expected) {
    throw new Error(`${algorithm}: SPKI is ${spki.length} bytes, expected ${expected}`);
  }
  return spki.subarray(SPKI_PREFIX_BYTES[algorithm]);
}

/** A P-256 pair, the public key as a 33-byte compressed point. */
function p256Pair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const uncompressed = rawPublic(publicKey, 'p256');
  const compressed = ECDH.convertKey(uncompressed, 'prime256v1', undefined, undefined, 'compressed');
  return { algorithm: ECDSA_P256, publicKey: hex(compressed), privateKeyPkcs8: pkcs8Hex(privateKey) };
}

/** An ML-DSA-87 pair, the public key as its 2592 raw bytes. */
function mlDsa87Pair() {
  const { publicKey, privateKey } = generateKeyPairSync('ml-dsa-87');
  return { algorithm: ML_DSA_87, publicKey: hex(rawPublic(publicKey, 'ml-dsa-87')), privateKeyPkcs8: pkcs8Hex(privateKey) };
}

/** Writes a fresh wallet pair to keys.json and returns the file's content. */
function makeKeys() {
  const keys = {
    about: 'The wallet pair of the stand-in signing server. Private halves included: keep this file out of git.',
    createdAt: new Date().toISOString(),
    [WALLET_KEY]: p256Pair(),
    [WALLET_POST_QUANTUM_KEY]: mlDsa87Pair(),
  };
  writeFileSync(KEYS_FILE, `${JSON.stringify(keys, null, 2)}\n`, { mode: 0o600 });
  return keys;
}

/**
 * The wallet pair, loaded from keys.json or made now. Returns
 * { created, publicKeys: { walletKey, walletPostQuantumKey } (hex),
 *   privateKeys: { walletKey, walletPostQuantumKey } (KeyObjects) }.
 * Each private key is checked against the public key stored beside it, so a
 * hand-edited file fails at boot rather than on the first signature.
 */
export function loadKeys() {
  const created = !existsSync(KEYS_FILE);
  const file = created ? makeKeys() : JSON.parse(readFileSync(KEYS_FILE, 'utf8'));
  const publicKeys = {};
  const privateKeys = {};
  for (const [role, algorithm] of [[WALLET_KEY, 'p256'], [WALLET_POST_QUANTUM_KEY, 'ml-dsa-87']]) {
    const entry = file[role];
    if (!entry || typeof entry.publicKey !== 'string' || typeof entry.privateKeyPkcs8 !== 'string') {
      throw new Error(`keys.json has no usable ${role}`);
    }
    const privateKey = createPrivateKey({ key: Buffer.from(entry.privateKeyPkcs8, 'hex'), format: 'der', type: 'pkcs8' });
    const derived = rawPublic(createPublicKey(privateKey), algorithm);
    const expected = algorithm === 'p256'
      ? ECDH.convertKey(derived, 'prime256v1', undefined, undefined, 'compressed')
      : derived;
    if (hex(expected) !== entry.publicKey) {
      throw new Error(`keys.json: the private ${role} does not match its publicKey`);
    }
    publicKeys[role] = entry.publicKey;
    privateKeys[role] = privateKey;
  }
  return { created, publicKeys, privateKeys };
}
