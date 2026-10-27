import { canonicalize } from './crypto/canonical.js';
import { ECDSA_P256, ML_DSA_87, signMessage } from './crypto/signatures.js';
import { WALLET_KEY, WALLET_POST_QUANTUM_KEY } from './keys.js';

/** True for a plain JSON object: not null, not an array. */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The reason a malformed /sign body is refused with. */
export const BAD_SHAPE = 'bad request shape';

/**
 * What POST /sign does (spec section 3): `body` is { transaction: { payload,
 * signatures } }. The two wallet signatures are made over the RFC 8785
 * canonical bytes of payload, walletKey as 64 bytes r || s over their
 * SHA-256 and walletPostQuantumKey as pure ML-DSA-87 (4627 bytes), and set
 * on signatures, replacing any present; everything else is left as it came.
 * Returns { ok: true, transaction } or { ok: false, reason } when
 * transaction, payload or signatures is not an object, or payload has no
 * canonical form.
 */
export function signTransaction(body, privateKeys) {
  if (!isObject(body) || !isObject(body.transaction)) return { ok: false, reason: BAD_SHAPE };
  const { payload, signatures } = body.transaction;
  if (!isObject(payload) || !isObject(signatures)) return { ok: false, reason: BAD_SHAPE };

  let message;
  try {
    message = Buffer.from(canonicalize(payload), 'utf8');
  } catch {
    return { ok: false, reason: BAD_SHAPE };
  }

  const signed = {
    ...signatures,
    [WALLET_KEY]: signMessage(ECDSA_P256, privateKeys[WALLET_KEY], message).toString('hex'),
    [WALLET_POST_QUANTUM_KEY]: signMessage(ML_DSA_87, privateKeys[WALLET_POST_QUANTUM_KEY], message).toString('hex'),
  };
  return { ok: true, transaction: { ...body.transaction, payload, signatures: signed } };
}
