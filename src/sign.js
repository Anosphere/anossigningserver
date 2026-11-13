import { ACCOUNT_KEYS, BROWSER_KEYS, creationCheck } from './checks/creation.js';
import { followUpCheck } from './checks/follow-ups.js';
import { CREATION, FOLLOW_UP, FUND_PROPOSAL, TRANSFER, TRANSFER_TO_FUND, kindOf } from './checks/kinds.js';
import { fundProposalCheck, transferCheck, transferToFundCheck } from './checks/transfers.js';
import { canonicalize } from './crypto/canonical.js';
import { decodeDigest, digestMatches, sha256 } from './crypto/hash.js';
import { decodePublicKey, decodeSignature, verifySignature } from './crypto/signatures.js';
import { WALLET_KEY, WALLET_POST_QUANTUM_KEY } from './keys.js';
import { findPair } from './pairs.js';

/** True for a plain JSON object: not null, not an array. */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The reason a malformed /sign body is refused with. */
export const BAD_SHAPE = 'bad request shape';

/** The reason when a request for anything but a creation comes without the signer's creation. */
const CREATION_MISSING = "creation is missing: send the signer account's creation with the request";

/** The reason when the creation names a wallet pair that is not one of this server's. */
const NOT_THIS_SERVERS = "the creation's wallet key is not one of this server's";

/** The one reason answered with 503: the pair could not sign. */
const KMS_UNAVAILABLE = 'kms unavailable';

/** The check of a kind's shape and ids, by the kind's family (checks/kinds.js). */
const SHAPE_AND_IDS = Object.freeze({
  [CREATION]: creationCheck,
  [TRANSFER]: transferCheck,
  [TRANSFER_TO_FUND]: transferToFundCheck,
  [FUND_PROPOSAL]: fundProposalCheck,
  [FOLLOW_UP]: followUpCheck,
});

const keysNamed = (...names) => ACCOUNT_KEYS.filter(({ name }) => names.includes(name));

/** Pair one: the person's signatures on everything but a creation are these two, both of them. */
const PAIR_ONE = keysNamed('key1', 'postQuantumKey1');

/** What is read of a creation that comes with a request: pair one and the wallet pair. Nothing else of it is read. */
const CREATION_KEYS = keysNamed('key1', 'postQuantumKey1', WALLET_KEY, WALLET_POST_QUANTUM_KEY);

const refuse = (reason) => ({ ok: false, status: 400, reason });

/**
 * What POST /sign does. `body` is { transaction: { payload, signatures },
 * creation: { payload } }: the thing to sign, and the creation of the
 * account that signs it. `pairs` are this server's wallet pairs (pairs.js).
 * The server asks nobody: what it checks, it checks from the request
 * alone. In this order; the first thing that fails is the answer.
 *
 *   1. The request: body, transaction, its payload and its signatures are
 *      objects, and the payload has a canonical form.
 *   2. The kind (checks/kinds.js kindOf), then that kind's shape and ids,
 *      the validators' checks that need no database (checks/). Check (d).
 *   3. The creation. For an accountCreation it is the transaction itself,
 *      and a creation in the body is not read. For every other kind,
 *      creation.payload.publicKeys must hold key1, postQuantumKey1,
 *      walletKey and walletPostQuantumKey as strings that decode for their
 *      algorithms. Nothing else of the creation is read, and its own
 *      signatures are neither sent nor checked.
 *   4. Check (a): the SHA-256 of the creation's key1 and postQuantumKey1
 *      strings, joined as sent, is the signer's account id, the value of
 *      the kind's signer field, compared as bytes. For a creation this is
 *      the accountId check of step 2.
 *   5. Check (b): the creation's two wallet keys are one of this server's
 *      pairs (pairs.js findPair). That pair signs.
 *   6. Check (c), over the canonical bytes of the payload. A creation: each
 *      of the six signatures of the keys the browser holds decodes and
 *      verifies against its key in the payload. Everything else:
 *      signatures.key1 and signatures.postQuantumKey1 are both there, and
 *      each decodes and verifies against the creation's key. Pair two's
 *      signatures are not looked at.
 *   7. The pair's sign. The two wallet signatures are made over the RFC
 *      8785 canonical bytes of payload, walletKey as 64 bytes r || s over
 *      their SHA-256 and walletPostQuantumKey as pure ML-DSA-87 (4627
 *      bytes), and set on signatures, replacing any present; everything
 *      else is left as it came.
 *
 * Checks (a) and (c) tie the request to the holder of pair one whatever
 * else the creation says: only that holder can sign for the account id
 * that pair one hashes to. The balance, the previous transaction, the
 * dates and everything else that needs a database or a clock are the
 * validators'.
 *
 * Resolves with one of three things:
 *   { ok: true, transaction, kind, signer, pair }: the signed transaction,
 *     the kind's name, the signer's account id as lowercase hex, the
 *     pair's number;
 *   { ok: false, status: 400, reason }: a check failed;
 *   { ok: false, status: 503, reason: 'kms unavailable', detail }: the
 *     pair could not sign; `detail` says which pair and what went wrong,
 *     for the log line.
 */
export async function signRequest(body, pairs) {
  // 1. The request.
  if (!isObject(body) || !isObject(body.transaction)) return refuse(BAD_SHAPE);
  const { payload, signatures } = body.transaction;
  if (!isObject(payload) || !isObject(signatures)) return refuse(BAD_SHAPE);

  let message;
  try {
    message = Buffer.from(canonicalize(payload), 'utf8');
  } catch {
    return refuse(BAD_SHAPE);
  }

  // 2. The kind, then its shape and ids: check (d).
  const { kind, reason: unknownKind } = kindOf(payload);
  if (unknownKind) return refuse(unknownKind);
  const problem = SHAPE_AND_IDS[kind.family](body.transaction, kind);
  if (problem) return refuse(problem);
  const isCreation = kind.family === CREATION;

  // 3. The creation: the transaction itself, or the one sent along.
  const creation = isCreation
    ? decodeKeys(payload.publicKeys, ACCOUNT_KEYS, 'payload')
    : readCreation(body.creation);
  if (creation.reason) return refuse(creation.reason);
  const { publicKeys, keys } = creation;

  // 4. Check (a): the signer's account id is the hash of pair one's keys.
  if (!isCreation && !digestMatches(payload[kind.signerField], sha256(publicKeys.key1 + publicKeys.postQuantumKey1))) {
    return refuse(`payload.${kind.signerField} is not the SHA-256 of the creation's key1 + postQuantumKey1`);
  }

  // 5. Check (b): the wallet pair is one of this server's.
  const pair = findPair(pairs, keys[WALLET_KEY], keys[WALLET_POST_QUANTUM_KEY]);
  if (!pair) return refuse(NOT_THIS_SERVERS);

  // 6. Check (c): the person's signatures.
  if (!isCreation && PAIR_ONE.some(({ name }) => signatures[name] === undefined)) {
    return refuse(`signatures.${PAIR_ONE[0].name} and signatures.${PAIR_ONE[1].name} must both be present`);
  }
  for (const { name, algorithm } of isCreation ? BROWSER_KEYS : PAIR_ONE) {
    const signature = decodeSignature(algorithm, signatures[name]);
    if (!signature) return refuse(`signatures.${name} is not a valid ${algorithm} signature`);
    if (!verifySignature(algorithm, keys[name], message, signature)) {
      const against = isCreation ? `payload.publicKeys.${name}` : `the account's ${name}`;
      return refuse(`signatures.${name} does not verify against ${against}`);
    }
  }

  // 7. The pair signs.
  let made;
  try {
    made = await pair.sign(message);
  } catch (err) {
    return {
      ok: false,
      status: 503,
      reason: KMS_UNAVAILABLE,
      detail: `pair ${pair.number}: ${err?.message ?? String(err)}`,
    };
  }
  const signed = {
    ...signatures,
    [WALLET_KEY]: made[WALLET_KEY].toString('hex'),
    [WALLET_POST_QUANTUM_KEY]: made[WALLET_POST_QUANTUM_KEY].toString('hex'),
  };
  return {
    ok: true,
    transaction: { ...body.transaction, payload, signatures: signed },
    kind: kind.name,
    signer: decodeDigest(payload[kind.signerField]).toString('hex'),
    pair: pair.number,
  };
}

/**
 * Step 3 for everything but a creation: the four keys of the creation that
 * came with the request. Returns { publicKeys, keys }, the strings as sent
 * and the decoded bytes by name, or { reason }.
 */
function readCreation(creation) {
  if (!isObject(creation) || !isObject(creation.payload) || !isObject(creation.payload.publicKeys)) {
    return { reason: CREATION_MISSING };
  }
  const { publicKeys } = creation.payload;
  for (const { name } of CREATION_KEYS) {
    if (typeof publicKeys[name] !== 'string') {
      return { reason: `creation.payload.publicKeys.${name} must be a string` };
    }
  }
  return decodeKeys(publicKeys, CREATION_KEYS, 'creation.payload');
}

/**
 * The keys `wanted` out of `publicKeys`, decoded for their algorithms.
 * Returns { publicKeys, keys } or { reason }, the reason naming the key
 * under `where`. A creation's own eight keys were decoded once already, in
 * step 2, so for them it never gives a reason.
 */
function decodeKeys(publicKeys, wanted, where) {
  const keys = {};
  for (const { name, algorithm } of wanted) {
    keys[name] = decodePublicKey(algorithm, publicKeys[name]);
    if (!keys[name]) {
      return { reason: `${where}.publicKeys.${name} is not a valid ${algorithm} public key` };
    }
  }
  return { publicKeys, keys };
}
