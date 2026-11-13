import { canonicalHash } from '../crypto/canonical.js';
import { decodeDigest, digestMatches } from '../crypto/hash.js';

/**
 * The shape and ids of the seven transactions a wallet sends besides a
 * creation: the validators' checks that need no database, copied with
 * their reasons from anossoftware.
 *
 *   - The five transfer types (anosTransfer, guardedAnosTransfer,
 *     vaultAnosTransfer, assistedAnosTransfer, escrowTransfer):
 *     src/transfer/transfer.service.js, checkShape and checks 1 and 4 of
 *     checkTransferSignaturesAndIds. The three ids are SHA-256 digests,
 *     amount is a positive integer as a decimal string that fits a BIGINT,
 *     transactionId is the SHA-256 of the canonical payload without it.
 *   - A transferToFund: src/fund/fund.service.js, checkTransferToFundShape
 *     and checks 1, 1b and 4 of checkTransferToFundSignaturesAndIds. The
 *     same, and accountIdTo is the fund and stakeFor one of the six
 *     purposes.
 *   - A fundProposal: src/fund/fund.service.js, checkProposalShape and
 *     checks 1, 4 and 5a of checkFundProposalSignaturesAndIds. accountId is
 *     the fund, guardianId is a digest, transactionId, and each payout's
 *     recipient, amount and purpose.
 *
 * Not here, of each shape function: that the body, its payload and its
 * signatures are objects, which is the first step of sign.js, and the
 * transactionType, which kindOf (kinds.js) has read before these run. The
 * signatures are verified in sign.js, against the signer's creation.
 *
 * Not copied, because it needs a database, a clock or a peer: that the
 * account exists, its type, its balance, the previous transaction, the
 * receiver, how far createdAt is from now, the stake's minimum, an
 * appointment, a held row.
 */

/** The largest value a BIGINT column holds. */
const MAX_BIGINT = 2n ** 63n - 1n;

/** How an amount must look, for the reasons that quote it. */
const AMOUNT_RULE = 'must be a positive integer (millionths of a unit) as a decimal string';

/**
 * The fund's account id: the SHA-256 of the word "anosFund", the accountId
 * of the validators' genesis fund account (anossoftware's
 * src/fund/fund-account.js).
 */
const FUND_ACCOUNT_ID = decodeDigest('b8f8da9cc80161e0705943de93dedfe850f0cab74b1939df806972df6ef61e24');

/** The six purposes an account may stake for, in the order of anossoftware's src/stakes/stake-purposes.js. */
const PURPOSE_NAMES = Object.freeze(['daoVote', 'moderator', 'attestor', 'guardian', 'validator', 'masterPod']);

/** True for a plain JSON object: not null, not an array. */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A transfer of one of the five types. Returns null when its shape and ids are right, else the validators' reason. */
export function transferCheck({ payload }) {
  const problem = checkShape(payload);
  if (problem) return problem;

  // 1. Ids and amount.
  if (!decodeDigest(payload.accountId)) return 'payload.accountId is not a SHA-256 digest';
  if (!decodeDigest(payload.accountIdTo)) return 'payload.accountIdTo is not a SHA-256 digest';
  if (!decodeDigest(payload.previousTransactionId)) return 'payload.previousTransactionId is not a SHA-256 digest';
  if (parseAmount(payload.amount) === null) return `payload.amount ${AMOUNT_RULE}`;

  // 4. transactionId: the hash of the payload without itself.
  return badTransactionId(payload);
}

/** A transferToFund. Returns null when its shape and ids are right, else the validators' reason. */
export function transferToFundCheck({ payload }) {
  const problem = checkTransferToFundShape(payload);
  if (problem) return problem;

  // 1. Ids and amount.
  if (!decodeDigest(payload.accountId)) return 'payload.accountId is not a SHA-256 digest';
  const accountIdTo = decodeDigest(payload.accountIdTo);
  if (!accountIdTo) return 'payload.accountIdTo is not a SHA-256 digest';
  if (!decodeDigest(payload.previousTransactionId)) return 'payload.previousTransactionId is not a SHA-256 digest';
  if (parseAmount(payload.amount) === null) return `payload.amount ${AMOUNT_RULE}`;

  // 1b. The fund and the purpose.
  if (!accountIdTo.equals(FUND_ACCOUNT_ID)) return 'payload.accountIdTo is not the fund';
  if (!PURPOSE_NAMES.includes(payload.stakeFor)) {
    return `payload.stakeFor must be one of ${PURPOSE_NAMES.join(', ')}`;
  }

  // 4. transactionId: the hash of the payload without itself.
  return badTransactionId(payload);
}

/** A fundProposal. Returns null when its shape and ids are right, else the validators' reason. */
export function fundProposalCheck({ payload }) {
  const problem = checkProposalShape(payload);
  if (problem) return problem;

  // 1. The fund and the proposer's id.
  const accountId = decodeDigest(payload.accountId);
  if (!accountId) return 'payload.accountId is not a SHA-256 digest';
  if (!accountId.equals(FUND_ACCOUNT_ID)) return 'payload.accountId is not the fund';
  if (!decodeDigest(payload.guardianId)) return 'payload.guardianId is not a SHA-256 digest';

  // 4. transactionId: the hash of the payload without itself.
  const badId = badTransactionId(payload);
  if (badId) return badId;

  // 5a. Each payout: recipient, amount, purpose.
  for (const [i, payout] of payload.payouts.entries()) {
    const recipient = decodeDigest(payout.accountIdTo);
    if (!recipient) return `payload.payouts[${i}].accountIdTo is not a SHA-256 digest`;
    if (recipient.equals(FUND_ACCOUNT_ID)) return `payload.payouts[${i}].accountIdTo is the fund`;
    if (parseAmount(payout.amount) === null) return `payload.payouts[${i}].amount ${AMOUNT_RULE}`;
    if (payout.stakeFor !== undefined && !PURPOSE_NAMES.includes(payout.stakeFor)) {
      return `payload.payouts[${i}].stakeFor must be one of ${PURPOSE_NAMES.join(', ')}`;
    }
  }
  return null;
}

/** An amount from a payload as a BigInt, or null when it is not a positive integer that fits a BIGINT. */
function parseAmount(amount) {
  if (typeof amount !== 'string' || !/^[1-9][0-9]*$/.test(amount)) return null;
  const value = BigInt(amount);
  return value > MAX_BIGINT ? null : value;
}

/**
 * Check 4: transactionId is the SHA-256 of the canonical payload without
 * its transactionId, which is how the web app makes every transfer-like
 * id. Returns the reason, or null when it is.
 */
function badTransactionId(payload) {
  const unsigned = { ...payload };
  delete unsigned.transactionId;
  if (!digestMatches(payload.transactionId, canonicalHash(unsigned))) {
    return 'payload.transactionId is not the SHA-256 of the canonical payload without transactionId';
  }
  return null;
}

/** Returns a description of the first structural problem with a transfer, or null if the shape is right. */
function checkShape(payload) {
  if (typeof payload.accountId !== 'string') return 'payload.accountId must be a string';
  if (typeof payload.transactionId !== 'string') return 'payload.transactionId must be a string';
  if (typeof payload.previousTransactionId !== 'string') return 'payload.previousTransactionId must be a string';
  if (typeof payload.amount !== 'string') return 'payload.amount must be a string';
  if (typeof payload.accountIdTo !== 'string') return 'payload.accountIdTo must be a string';
  if (typeof payload.createdAt !== 'string') return 'payload.createdAt must be a string';
  return null;
}

/** Returns a description of the first structural problem with a transferToFund, or null. */
function checkTransferToFundShape(payload) {
  if (typeof payload.accountId !== 'string') return 'payload.accountId must be a string';
  if (typeof payload.transactionId !== 'string') return 'payload.transactionId must be a string';
  if (typeof payload.previousTransactionId !== 'string') return 'payload.previousTransactionId must be a string';
  if (typeof payload.amount !== 'string') return 'payload.amount must be a string';
  if (typeof payload.accountIdTo !== 'string') return 'payload.accountIdTo must be a string';
  if (typeof payload.createdAt !== 'string') return 'payload.createdAt must be a string';
  if (typeof payload.stakeFor !== 'string') return 'payload.stakeFor must be a string';
  return null;
}

/** Returns a description of the first structural problem with a fundProposal, or null. */
function checkProposalShape(payload) {
  if (typeof payload.accountId !== 'string') return 'payload.accountId must be a string';
  if (typeof payload.guardianId !== 'string') return 'payload.guardianId must be a string';
  if (typeof payload.createdAt !== 'string') return 'payload.createdAt must be a string';
  if (typeof payload.transactionId !== 'string') return 'payload.transactionId must be a string';
  if (!Array.isArray(payload.payouts) || payload.payouts.length === 0) {
    return 'payload.payouts must be an array with at least one payout';
  }
  for (const [i, payout] of payload.payouts.entries()) {
    if (!isObject(payout)) return `payload.payouts[${i}] must be an object`;
    if (typeof payout.accountIdTo !== 'string') return `payload.payouts[${i}].accountIdTo must be a string`;
    if (typeof payout.amount !== 'string') return `payload.payouts[${i}].amount must be a string`;
    if (typeof payout.reason !== 'string') return `payload.payouts[${i}].reason must be a string`;
    if (payout.stakeFor !== undefined && typeof payout.stakeFor !== 'string') {
      return `payload.payouts[${i}].stakeFor must be a string when present`;
    }
  }
  return null;
}
