import { digestMatches, sha256 } from '../crypto/hash.js';
import { ECDSA_P256, ML_DSA_87, decodePublicKey } from '../crypto/signatures.js';

/**
 * The shape and ids of an account creation, { payload, signatures }: the
 * validators' check of POST /create-account up to its signatures, copied
 * with its reasons from anossoftware's src/accounts/accounts.service.js,
 * checkShape and checkCreateAccountSignaturesAndIds:
 *
 *   - checkShape, asking for six signature strings in place of eight: the
 *     wallet pair's two are what this server adds;
 *   - each of the eight public keys decodes for its algorithm;
 *   - check 2, accountId is the SHA-256 of key1 + postQuantumKey1, the two
 *     key strings exactly as sent, joined with nothing between them;
 *   - check 3, transactionId is the SHA-256 of all eight public key strings
 *     as sent, joined in the order of ACCOUNT_KEYS.
 *
 * Not here, of checkShape: that the body, its payload and its signatures
 * are objects, which is the first step of sign.js. The six signatures
 * themselves are verified in sign.js, after the wallet pair is found. Not
 * copied, because it needs a database or a peer: that nothing with these
 * ids exists yet, and the masterpod's binding.
 */

/**
 * The eight keys every account has, in the order the web app lists them.
 * The order matters: transactionId is a hash over the keys in this order.
 * Each classical P-256 key is paired with a post-quantum ML-DSA-87 key.
 *
 * A copy of anossoftware's src/accounts/account-keys.js.
 */
export const ACCOUNT_KEYS = Object.freeze([
  { name: 'key1', algorithm: ECDSA_P256 },
  { name: 'postQuantumKey1', algorithm: ML_DSA_87 },
  { name: 'key2', algorithm: ECDSA_P256 },
  { name: 'postQuantumKey2', algorithm: ML_DSA_87 },
  { name: 'breakGlassKey', algorithm: ECDSA_P256 },
  { name: 'breakGlassPostQuantumKey', algorithm: ML_DSA_87 },
  { name: 'walletKey', algorithm: ECDSA_P256 },
  { name: 'walletPostQuantumKey', algorithm: ML_DSA_87 },
].map(Object.freeze));

/** The six keys the browser holds, which sign a creation before it comes here: all but the wallet pair. */
export const BROWSER_KEYS = Object.freeze(
  ACCOUNT_KEYS.filter(({ name }) => name !== 'walletKey' && name !== 'walletPostQuantumKey'),
);

/** The account types a creation may ask for, as anossoftware's src/accounts/account-types.js lists them. */
const ACCOUNT_TYPES = Object.freeze(['spending', 'guarded', 'vault', 'assisted']);

/** True for a plain JSON object: not null, not an array. */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Returns null when the creation's shape and ids are right, else the validators' reason. */
export function creationCheck({ payload, signatures }) {
  const problem = checkShape(payload, signatures);
  if (problem) return problem;

  const { publicKeys } = payload;
  for (const { name, algorithm } of ACCOUNT_KEYS) {
    if (!decodePublicKey(algorithm, publicKeys[name])) {
      return `payload.publicKeys.${name} is not a valid ${algorithm} public key`;
    }
  }

  // 2. accountId.
  if (!digestMatches(payload.accountId, sha256(publicKeys.key1 + publicKeys.postQuantumKey1))) {
    return 'payload.accountId is not the SHA-256 of key1 + postQuantumKey1';
  }

  // 3. transactionId.
  if (!digestMatches(payload.transactionId, sha256(ACCOUNT_KEYS.map(({ name }) => publicKeys[name]).join('')))) {
    return 'payload.transactionId is not the SHA-256 of the eight public keys in order';
  }
  return null;
}

/** Returns a description of the first structural problem, or null if the shape is right. */
function checkShape(payload, signatures) {
  if (typeof payload.accountId !== 'string') return 'payload.accountId must be a string';
  if (typeof payload.transactionId !== 'string') return 'payload.transactionId must be a string';
  if (!ACCOUNT_TYPES.includes(payload.accountType)) {
    return `payload.accountType must be one of ${ACCOUNT_TYPES.join(', ')}`;
  }
  if (!isObject(payload.publicKeys)) return 'payload.publicKeys must be an object';

  for (const { name } of ACCOUNT_KEYS) {
    if (typeof payload.publicKeys[name] !== 'string') {
      return `payload.publicKeys.${name} must be a string`;
    }
    if (BROWSER_KEYS.some((key) => key.name === name) && typeof signatures[name] !== 'string') {
      return `signatures.${name} must be a string`;
    }
  }
  return null;
}
