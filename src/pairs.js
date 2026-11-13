import { randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { KMS, LOCAL } from './config.js';
import { derToRaw } from './crypto/der.js';
import { sha256 } from './crypto/hash.js';
import { ECDSA_P256, ML_DSA_87, signMessage, verifySignature } from './crypto/signatures.js';
import { WALLET_KEY, WALLET_POST_QUANTUM_KEY, loadKeys } from './keys.js';
import { ask as askGoogle } from './kms.js';

/**
 * The wallet pairs this server signs with. A pair is a P-256 key and an
 * ML-DSA-87 key; every account names one pair for life, in its creation,
 * and that pair co-signs everything the account sends.
 *
 * A pair has one shape in both key stores:
 *
 *   number                the pair's number, from 1
 *   walletKey             its P-256 public key, hex, the 33-byte compressed point
 *   walletPostQuantumKey  its ML-DSA-87 public key, hex, 2592 bytes
 *   sign(message)         resolves with { walletKey, walletPostQuantumKey }:
 *                         the two signatures over `message` (a Buffer) as
 *                         Buffers, 64 bytes r || s over its SHA-256 and
 *                         4627 bytes of pure ML-DSA-87
 *
 * The local key store has one pair, number 1, the one in keys.json
 * (keys.js). The kms key store has the pairs listed in
 * network/wallet-pairs.json: the list holds the public halves and the
 * names of the keys in Google Cloud KMS, and the private halves never
 * leave Google (kms.js).
 */

/** The list of the kms key store's pairs, from the repo root. The key ceremony writes it. */
export const WALLET_PAIRS_FILE = 'network/wallet-pairs.json';

const WALLET_PAIRS_PATH = fileURLToPath(new URL(`../${WALLET_PAIRS_FILE}`, import.meta.url));

/** How long Google has to answer both halves of one signature, in milliseconds. */
export const KMS_TIMEOUT_MS = 10_000;

/** The two halves of a pair: its name in a signatures object, its algorithm, the length of its public key in hex. */
const HALVES = Object.freeze([
  { name: WALLET_KEY, algorithm: ECDSA_P256, hexLength: 66 },
  { name: WALLET_POST_QUANTUM_KEY, algorithm: ML_DSA_87, hexLength: 5184 },
].map(Object.freeze));

/** What follows the key ring's name in a key version's name. */
const VERSION_TAIL = /^\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/[1-9][0-9]*$/;

/** What every pair signs at boot (bootCheck). */
const BOOT_MESSAGE = Buffer.from('signingserver boot check', 'utf8');

/** True for a plain JSON object: not null, not an array. */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The pairs of the key store `config.keyStore` names (config.js). Resolves
 * with { keyStore, pairs, created }: `created` is true when the local key
 * store just wrote a new keys.json, for the boot line. Rejects when
 * keys.json is unusable (keys.js) or the list is refused (kmsPairs).
 */
export async function loadPairs(config) {
  if (config.keyStore === KMS) {
    return { keyStore: KMS, pairs: kmsPairs(WALLET_PAIRS_PATH, askGoogle), created: false };
  }
  const keys = loadKeys();
  return { keyStore: LOCAL, pairs: Object.freeze([localPair(keys)]), created: keys.created };
}

/** The one pair of the local key store: keys.json's, signing with its two key objects. */
function localPair(keys) {
  return Object.freeze({
    number: 1,
    [WALLET_KEY]: keys.publicKeys[WALLET_KEY],
    [WALLET_POST_QUANTUM_KEY]: keys.publicKeys[WALLET_POST_QUANTUM_KEY],
    sign: async (message) => ({
      [WALLET_KEY]: signMessage(ECDSA_P256, keys.privateKeys[WALLET_KEY], message),
      [WALLET_POST_QUANTUM_KEY]: signMessage(ML_DSA_87, keys.privateKeys[WALLET_POST_QUANTUM_KEY], message),
    }),
  });
}

/**
 * The pairs of the kms key store: the list in `file`, in the file's order.
 * `ask(versionName, { digest })` or `ask(versionName, { data })` resolves
 * with a signature by that key version as Google gives it; it is kms.js's
 * ask on signer1 and signer2. Throws when the list is refused (readList).
 */
export function kmsPairs(file, ask) {
  return Object.freeze(readList(file).map(({ versions, ...publicHalf }) => Object.freeze({
    ...publicHalf,
    sign: (message) => signWithKms(publicHalf, versions, ask, message),
  })));
}

/**
 * Reads the list of pairs:
 *
 *   {
 *     "about": "...",
 *     "keyRing": "projects/<project>/locations/<location>/keyRings/<ring>",
 *     "pairs": [
 *       {
 *         "number": 1,
 *         "walletKey": "<66 hex characters>",
 *         "walletPostQuantumKey": "<5184 hex characters>",
 *         "walletKeyVersion": "<keyRing>/cryptoKeys/<name>/cryptoKeyVersions/<number>",
 *         "walletPostQuantumKeyVersion": "<keyRing>/cryptoKeys/<name>/cryptoKeyVersions/<number>"
 *       }
 *     ]
 *   }
 *
 * Refused, each with its reason: a file that is missing or not JSON; an
 * empty `pairs`; a number that is not a positive integer, or comes twice;
 * a public key of the wrong length for its algorithm, or one that comes
 * twice; a version name that is not `keyRing` followed by
 * /cryptoKeys/<name>/cryptoKeyVersions/<number>. The count is what the
 * file holds, and the numbers may have gaps. Returns one
 * { number, walletKey, walletPostQuantumKey, versions } per pair, with
 * `versions` the two version names by half.
 */
function readList(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error(err.code === 'ENOENT' ? `${file} is missing` : `${file} cannot be read: ${err.message}`);
  }
  let list;
  try {
    list = JSON.parse(text);
  } catch {
    throw new Error(`${file} is not JSON`);
  }
  const refused = (problem) => new Error(`${file}: ${problem}`);

  if (!isObject(list)) throw refused('the list must be a JSON object');
  const { keyRing, pairs } = list;
  if (typeof keyRing !== 'string' || keyRing === '') throw refused('keyRing must be a string');
  if (!Array.isArray(pairs) || pairs.length === 0) throw refused('pairs must be an array with at least one pair');

  const numbers = new Set();
  const publicKeys = new Set();
  return pairs.map((entry, i) => {
    if (!isObject(entry)) throw refused(`pairs[${i}] must be an object`);
    const { number } = entry;
    if (!Number.isSafeInteger(number) || number < 1) throw refused(`pairs[${i}].number must be a positive integer`);
    if (numbers.has(number)) throw refused(`the number ${number} comes twice`);
    numbers.add(number);

    const versions = {};
    for (const { name, hexLength } of HALVES) {
      const publicKey = entry[name];
      if (typeof publicKey !== 'string' || publicKey.length !== hexLength || !/^[0-9a-f]+$/i.test(publicKey)) {
        throw refused(`pair ${number}: ${name} must be ${hexLength} hex characters`);
      }
      if (publicKeys.has(publicKey.toLowerCase())) throw refused(`pair ${number}: its ${name} comes twice`);
      publicKeys.add(publicKey.toLowerCase());

      const version = entry[`${name}Version`];
      if (typeof version !== 'string' || !version.startsWith(keyRing) || !VERSION_TAIL.test(version.slice(keyRing.length))) {
        throw refused(`pair ${number}: ${name}Version must be keyRing followed by /cryptoKeys/<name>/cryptoKeyVersions/<number>`);
      }
      versions[name] = version;
    }
    return { number, [WALLET_KEY]: entry[WALLET_KEY], [WALLET_POST_QUANTUM_KEY]: entry[WALLET_POST_QUANTUM_KEY], versions };
  });
}

/**
 * One signature by a pair of the kms key store. The P-256 half is asked
 * with the SHA-256 of the message; the answer is DER and is turned into the
 * 64 bytes r || s (crypto/der.js). The ML-DSA-87 half is asked with the
 * message itself. Both are asked at once and get KMS_TIMEOUT_MS together;
 * then both are verified against the pair's public keys, so a signature
 * that would not pass a validator never leaves this server. Rejects, with
 * what went wrong as the error's message, when Google does not answer in
 * time, answers an error, or answers a signature that does not verify.
 */
async function signWithKms(pair, versions, ask, message) {
  const [der, postQuantum] = await inTime(
    Promise.all([
      ask(versions[WALLET_KEY], { digest: sha256(message) }),
      ask(versions[WALLET_POST_QUANTUM_KEY], { data: message }),
    ]),
    KMS_TIMEOUT_MS,
  );
  const signatures = {
    [WALLET_KEY]: derToRaw(der),
    [WALLET_POST_QUANTUM_KEY]: Buffer.from(postQuantum),
  };
  const bad = badSignature(pair, message, signatures);
  if (bad) throw new Error(bad);
  return signatures;
}

/** `work`, or a rejection when it has not settled within `ms`. */
function inTime(work, ms) {
  let timer;
  const late = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`no answer within ${ms / 1000} seconds`)), ms);
  });
  return Promise.race([work, late]).finally(() => clearTimeout(timer));
}

/** Null when both of `signatures` are the pair's over `message`, else which one is not. */
function badSignature(pair, message, signatures) {
  for (const { name, algorithm } of HALVES) {
    if (!verifySignature(algorithm, Buffer.from(pair[name], 'hex'), message, signatures[name])) {
      return `the ${name} signature does not verify against the pair's public key`;
    }
  }
  return null;
}

/**
 * The pair whose two public keys are `walletKey` and `walletPostQuantumKey`
 * (Buffers), compared as bytes, or null. Both must belong to the same pair.
 */
export function findPair(pairs, walletKey, walletPostQuantumKey) {
  return pairs.find((pair) =>
    Buffer.from(pair[WALLET_KEY], 'hex').equals(walletKey)
    && Buffer.from(pair[WALLET_POST_QUANTUM_KEY], 'hex').equals(walletPostQuantumKey)) ?? null;
}

/** One of the pairs, picked at random: the pair a new account gets. */
export function randomPair(pairs) {
  return pairs[randomInt(pairs.length)];
}

/**
 * The boot check: each pair, one after the other, signs a fixed message,
 * and both signatures are verified against the pair's public keys with the
 * validators' verify. Resolves with null when every pair passes, else with
 * { number, reason } for the first pair that fails; the pairs after it are
 * not tried.
 */
export async function bootCheck(pairs) {
  for (const pair of pairs) {
    let signatures;
    try {
      signatures = await pair.sign(BOOT_MESSAGE);
    } catch (err) {
      return { number: pair.number, reason: err?.message ?? String(err) };
    }
    const bad = badSignature(pair, BOOT_MESSAGE, signatures);
    if (bad) return { number: pair.number, reason: bad };
  }
  return null;
}
