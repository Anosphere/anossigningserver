/**
 * The 16 kinds of thing the wallet has this server sign, and which field of
 * a payload names its signer. Eight are transactions, told apart by
 * payload.transactionType; eight are follow-ups, told apart by
 * payload.type. A validator route reads the kind from the same field, so a
 * payload has one kind and one signer for the validators too.
 *
 * Each kind has a family, which says which check of this folder covers its
 * shape and ids (creation.js, transfers.js, follow-ups.js), and a signer
 * field: the account that signs is not always the one in accountId. A fund
 * proposal's accountId is the fund and its signer is guardianId; an
 * attestation's signer is attestorId, a guardian vote's guardianId, an
 * escrow verdict's arbitratorId.
 *
 * Not among them, and so refused: a breakGlassTransfer and a
 * breakGlassCancel. The break-glass pair signs those alone, and a validator
 * refuses a wallet pair's signature beside it.
 */

/** The five families. */
export const CREATION = 'creation';
export const TRANSFER = 'transfer';
export const TRANSFER_TO_FUND = 'transferToFund';
export const FUND_PROPOSAL = 'fundProposal';
export const FOLLOW_UP = 'followUp';

const kind = (name, family, signerField) => Object.freeze({ name, family, signerField });

const byName = (kinds) => new Map(kinds.map((entry) => [entry.name, entry]));

/** The eight kinds told apart by payload.transactionType. */
const BY_TRANSACTION_TYPE = byName([
  kind('accountCreation', CREATION, 'accountId'),
  kind('anosTransfer', TRANSFER, 'accountId'),
  kind('guardedAnosTransfer', TRANSFER, 'accountId'),
  kind('vaultAnosTransfer', TRANSFER, 'accountId'),
  kind('assistedAnosTransfer', TRANSFER, 'accountId'),
  kind('escrowTransfer', TRANSFER, 'accountId'),
  kind('transferToFund', TRANSFER_TO_FUND, 'accountId'),
  kind('fundProposal', FUND_PROPOSAL, 'guardianId'),
]);

/** The eight kinds told apart by payload.type: the follow-ups. */
const BY_TYPE = byName([
  kind('attestation', FOLLOW_UP, 'attestorId'),
  kind('assistedTransferCancel', FOLLOW_UP, 'accountId'),
  kind('lockedTransferCancel', FOLLOW_UP, 'accountId'),
  kind('guardianVote', FOLLOW_UP, 'guardianId'),
  kind('escrowSuccess', FOLLOW_UP, 'accountId'),
  kind('escrowCancel', FOLLOW_UP, 'accountId'),
  kind('escrowDispute', FOLLOW_UP, 'accountId'),
  kind('escrowVerdict', FOLLOW_UP, 'arbitratorId'),
]);

/**
 * The kind of `payload` (an object): { kind } with { name, family,
 * signerField }, or { reason }. A field counts as present when the payload
 * has it as its own key, whatever its value. A payload with both fields is
 * refused, so that one request can never be read as two kinds. No reason
 * repeats a value the sender chose.
 */
export function kindOf(payload) {
  const hasTransactionType = Object.hasOwn(payload, 'transactionType');
  const hasType = Object.hasOwn(payload, 'type');
  if (!hasTransactionType && !hasType) return { reason: 'payload has neither transactionType nor type' };
  if (hasTransactionType && hasType) return { reason: 'payload has both transactionType and type' };

  const [field, kinds] = hasTransactionType ? ['transactionType', BY_TRANSACTION_TYPE] : ['type', BY_TYPE];
  const value = payload[field];
  const found = typeof value === 'string' ? kinds.get(value) : undefined;
  return found ? { kind: found } : { reason: `payload.${field} is not a kind this server signs` };
}
