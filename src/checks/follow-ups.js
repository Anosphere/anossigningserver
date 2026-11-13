import { decodeDigest } from '../crypto/hash.js';

/**
 * The shape and ids of a follow-up: a signed object attached to a
 * transaction that waits on the validators (an attestation, a cancel, a
 * guardian's vote, an escrow signature or verdict). Its payload is
 * { type, transactionId, <the signer field>, signedAt, ...the kind's own
 * fields }; it has no id of its own.
 *
 * The validators' checks that need no database, copied with their reasons
 * from anossoftware's src/attachments/attachments.service.js:
 * checkAttachmentShape, with each kind's own checkShape, then the two id
 * lines of checkAttachmentSignatures: payload.transactionId and the signer
 * field are SHA-256 digests. Each kind's own checkShape is its module's
 * there (src/assisted-transfers/, src/locked-transactions/, src/fund/,
 * src/escrow/); five of the eight have nothing of their own to check.
 *
 * Not here, of checkAttachmentShape: that the body, its payload and its
 * signatures are objects, which is the first step of sign.js, and the
 * type, which kindOf (kinds.js) has read: it hands the kind in. The
 * signatures are verified in sign.js, against the signer's creation.
 *
 * Not copied, because it needs a database or a clock: the held row, the
 * signer's account and stake, a vote's closing time, a cancel's wait.
 */

/** What a guardian's vote may be: anossoftware's src/fund/fund.queries.js VOTES. */
const VOTES = Object.freeze(['for', 'against']);

/** What an arbitrator's verdict may be: anossoftware's src/escrow/escrow.queries.js VERDICTS. */
const VERDICTS = Object.freeze(['success', 'cancel']);

/**
 * The checkShape of the three kinds that have fields of their own, by the
 * kind's name: a reason for the first problem, or null. An attestation
 * also names the transfer's sender; a guardianVote carries its vote; an
 * escrowVerdict its verdict.
 */
const OWN_SHAPE = new Map([
  ['attestation', (payload) => {
    if (typeof payload.accountId !== 'string') return 'payload.accountId must be a string';
    return null;
  }],
  ['guardianVote', (payload) => {
    if (!VOTES.includes(payload.vote)) return `payload.vote must be ${VOTES.map((vote) => `"${vote}"`).join(' or ')}`;
    return null;
  }],
  ['escrowVerdict', (payload) => {
    if (!VERDICTS.includes(payload.verdict)) {
      return `payload.verdict must be ${VERDICTS.map((verdict) => `"${verdict}"`).join(' or ')}`;
    }
    return null;
  }],
]);

/**
 * A follow-up of `kind` (kinds.js: { name, signerField }). Returns null
 * when its shape and ids are right, else the validators' reason.
 */
export function followUpCheck({ payload }, kind) {
  // The common shape, then the kind's own.
  if (typeof payload.transactionId !== 'string') return 'payload.transactionId must be a string';
  if (typeof payload[kind.signerField] !== 'string') return `payload.${kind.signerField} must be a string`;
  if (typeof payload.signedAt !== 'string') return 'payload.signedAt must be a string';
  const own = OWN_SHAPE.get(kind.name)?.(payload) ?? null;
  if (own) return own;

  // The ids.
  if (!decodeDigest(payload.transactionId)) return 'payload.transactionId is not a SHA-256 digest';
  if (!decodeDigest(payload[kind.signerField])) return `payload.${kind.signerField} is not a SHA-256 digest`;
  return null;
}
