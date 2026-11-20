/**
 * The one call to the masterpod: POST /check-signing-passkey (masterpod
 * spec section 22; 2026-11-20,
 * forclaude/second-key-and-signing-passkey-plan-1.md). Before this server
 * signs anything but a creation, it asks the masterpod whether the passkey
 * answer that came with the request is from a passkey of the anoPod that
 * made the signer's account, and is an answer to the challenge this
 * server worked out from the exact thing it is asked to sign (sign.js,
 * step 7). The masterpod holds the passkeys' public keys; this server
 * holds none and believes the masterpod's answer. Shaped like the
 * validators' masterpod.client.js: a fetch with a time limit, and every
 * failure one outcome.
 */

/**
 * How long the masterpod has to answer, in milliseconds. It stands in
 * front of Google's 10 seconds (pairs.js KMS_TIMEOUT_MS), so one signature
 * stays under the 15 seconds the wallet waits for a signing server.
 */
export const MASTERPOD_TIMEOUT_MS = 4_000;

/** A refusal's reason as the masterpod words them: a short phrase of letters, digits and spaces. Anything else is not repeated. */
const REASON = /^[A-Za-z0-9 ]{1,60}$/;

/**
 * Asks the masterpod at `masterpodUrl` about one passkey answer:
 * `accountId` and `challenge` as 64 hex characters, `assertion` the
 * WebAuthn JSON as the wallet sent it. Resolves with one of three things
 * and never rejects:
 *   { answered: true, verified: true }: a 200 that says verified: true.
 *   { answered: true, verified: false, reason }: a 4xx, the masterpod's
 *     own no. `reason` is its error phrase, or "HTTP <status>" when the
 *     body has none that reads like one.
 *   { answered: false, detail }: everything else. No answer within
 *     MASTERPOD_TIMEOUT_MS, the network failed, a redirect (not followed:
 *     another address must never answer in the masterpod's place), a 5xx,
 *     or a 200 that does not say verified: true.
 */
export async function checkSigningPasskey(masterpodUrl, accountId, challenge, assertion) {
  let response;
  try {
    response = await fetch(`${masterpodUrl}/check-signing-passkey`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accountId, challenge, assertion }),
      redirect: 'manual',
      signal: AbortSignal.timeout(MASTERPOD_TIMEOUT_MS),
    });
  } catch (err) {
    return { answered: false, detail: err?.message ?? String(err) };
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    // Not JSON, or the time ran out while the body came: the status decides.
  }
  if (response.status === 200) {
    return body?.verified === true ? { answered: true, verified: true } : { answered: false, detail: 'HTTP 200 without verified: true' };
  }
  if (response.status >= 400 && response.status < 500) {
    const reason = typeof body?.error === 'string' && REASON.test(body.error) ? body.error : `HTTP ${response.status}`;
    return { answered: true, verified: false, reason };
  }
  return { answered: false, detail: `HTTP ${response.status}` };
}
