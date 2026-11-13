# signingserver

The signing server holds the wallet pairs and signs with them. A wallet
pair is a P-256 key and an ML-DSA-87 key. Every account names one pair
for life, in its creation, and that pair co-signs everything the account
sends. An Express 5 server: no database, no auth, no CORS (only the
wallet's proxy calls it).

It checks a request before it signs it, and it asks nobody: what it
checks, it checks from the request alone. The balance, the previous
transaction, the dates and everything else that needs a database or a
clock are the validators'.

This README is the server's spec. What the wallet needs of it (the two
routes, the request and the answers) is also section 3 of
`docs/schemas.md` in the wallet's repo.

## Running it

```bash
npm install
npm start          # PORT=3300 by default; npm run dev restarts on file changes
```

Three settings, read from the environment at boot (`src/config.js`):

| Setting     | Default                | What it is |
| ----------- | ---------------------- | ---------- |
| `KEY_STORE` | `local`                | where the wallet pairs live, `local` or `kms`; any other value is refused at boot |
| `PORT`      | `3300`                 | the port to listen on |
| `HOST`      | unset: every interface | the address to listen on |

Two key stores, with the same checks in both:

- `local`: one pair, the number 1, in `keys.json`. This Mac uses it.
- `kms`: the pairs listed in `network/wallet-pairs.json`, their private
  halves in Google Cloud KMS. The two Google Cloud machines, signer1 and
  signer2, use it: `KEY_STORE=kms`, `PORT=8300` and `HOST=127.0.0.1`, in
  the file `/etc/signingserver/env`, which the unit reads when it exists.

The first boot writes `keys.json` in the project root: a P-256 pair and an
ML-DSA-87 pair from `node:crypto`, private keys as PKCS#8 DER in hex, public
keys raw (the SPKI prefix cut): 33 bytes compressed and 2592 bytes. The file
is git-ignored. Every boot checks each private key against its public key and
logs the two public keys.

That is the `local` key store. The `kms` key store has no `keys.json`.

## On signing1

signing1 keeps the software of `c614b21`, the stand-in that signs without
checking, until its service is stopped at the phase 3 launch. It is not
pulled again, and this section describes it as it runs there.

On the testnet the signing server runs on one Hetzner server of its own,
signing1, which only the two wallet servers may reach. The plan is
`forclaude/wallet-deploy-plan-1.md` beside the repos, section 4; the
operator runs it paste by paste, and nothing runs against the server from
a chat.

- The code is the clone of this repository at
  `/opt/signingserver/signingserver`, owned by the system user
  `signingserver`, home `/opt/signingserver`. No env file: the port is
  the default, 3300.
- The first boot is run by hand as that user, before the unit ever
  starts: it writes `keys.json` in the clone, prints the two public keys
  and is stopped after five seconds. The unit runs with
  `ProtectSystem=strict`, which makes the file system read-only to it,
  so it cannot write the file itself.
- The unit is `deploy/signingserver.service`, on 3300, put in place by
  `scripts/install-system-files.sh`, run as root from the repo root; the
  script enables the unit and restarts it, and runs again after any pull
  that touched `deploy/`.
- Custody: `keys.json` holds the wallet pair's private halves; every
  account carries that pair's public halves and every transfer is
  co-signed by it, so a lost file strands every account. The file is
  copied into the password manager and never printed, pasted or opened
  in a chat; its SHA-256 on the server and on the copy must be equal.
  Restoring one day: the file back to the same path, owner
  `signingserver`, mode 0600, then `systemctl restart signingserver`.
- The firewall admits 3300 from the two wallet servers only,
  89.167.121.152 and 178.105.176.147, and 22 from anywhere.

Updating (the plan, section 10): the pull as `signingserver`, `npm ci`
when the pull names `package-lock.json`, then the install script, which
restarts the unit; the key file is not touched by any of it.

    sudo -iu signingserver git -C /opt/signingserver/signingserver pull --ff-only
    sudo -iu signingserver bash -c 'cd /opt/signingserver/signingserver && npm ci'
    sh /opt/signingserver/signingserver/scripts/install-system-files.sh

## Routes

| Route               | Answer |
| ------------------- | ------ |
| `GET /`             | the text `signingserver` |
| `GET /health`       | `200 { status: "ok", uptime, keyStore, pairs }`: `keyStore` is `local` or `kms`, `pairs` the number of pairs |
| `GET /public-keys`  | `200 { walletKey: hex (33 bytes), walletPostQuantumKey: hex (2592 bytes) }`: the two public keys of one pair, picked at random at every call |
| `POST /sign`        | body `{ transaction: { payload: object, signatures: object }, creation: { payload: object } }`; `200 { transaction }`, `400 { error: reason }` or `503 { error: "kms unavailable" }` |

JSON limit 1 MB (a creation is about 60 KB). Unknown path: `404 { error:
"Not Found", path }`.

The wallet asks `GET /public-keys` for every new account and puts the two
keys into the account's creation. From then on that pair signs for the
account.

`POST /sign`:

- `transaction` is the thing to sign: its `payload`, and in `signatures`
  what the person signed already.
- `creation` is the creation of the account that signs: its `payload`
  alone, without its eight signatures. For an `accountCreation` the
  creation is the transaction itself, and a `creation` in the body is not
  read.
- `200 { transaction }`: the transaction with `signatures.walletKey` (64
  bytes r‖s over the SHA-256 of the RFC 8785 canonical bytes of
  `payload`) and `signatures.walletPostQuantumKey` (4627 bytes, pure
  ML-DSA-87, empty context, over the canonical bytes) set, both hex,
  replacing any present, everything else untouched.
- `400 { error: reason }`: a check failed. Nothing was signed.
- `503 { error: "kms unavailable" }`: every check passed and the pair
  could not sign. Nothing was signed, and the same request can be sent
  again, here or to the other signing server. Signing the same thing
  twice does no harm.

## What it checks before it signs

Four checks, which need no database and no other server:

- (a) the signer's account id is the hash of pair one's public keys in the
  signer's creation;
- (b) the wallet pair that creation names is one of this server's, which
  also says which pair signs;
- (c) the person's signatures on the thing to sign verify;
- (d) the thing is a kind the server knows, with the right shape and the
  right id.

They run in this order. The first thing that fails is the answer, as
`400 { error: reason }`.

**1. The request.** `body`, `transaction`, its `payload` and its
`signatures` are objects, and the payload has a canonical form.

    bad request shape

**2. The kind, then that kind's shape and ids: check (d).** The kind is
read from `payload.transactionType` or from `payload.type` (the 16 kinds,
below). A field counts as present when the payload has it as its own key,
whatever its value. A payload with both is refused, so that one request
can never be read as two kinds. A `breakGlassTransfer` and a
`breakGlassCancel` are not among the 16 and get the last two reasons.

    payload has neither transactionType nor type
    payload has both transactionType and type
    payload.transactionType is not a kind this server signs
    payload.type is not a kind this server signs

Then the kind's shape and ids: the validators' checks that need no
database, copied from anossoftware with their reasons (`src/checks/`).

An `accountCreation`. `<name>` is one of the eight keys, in the order
`key1`, `postQuantumKey1`, `key2`, `postQuantumKey2`, `breakGlassKey`,
`breakGlassPostQuantumKey`, `walletKey`, `walletPostQuantumKey`;
`<algorithm>` is `ecdsa-p256` or `ml-dsa-87`. The signatures asked for are
the six of the keys the browser holds: the wallet pair's two are what this
server adds.

    payload.accountId must be a string
    payload.transactionId must be a string
    payload.accountType must be one of spending, guarded, vault, assisted
    payload.publicKeys must be an object
    payload.publicKeys.<name> must be a string
    signatures.<name> must be a string
    payload.publicKeys.<name> is not a valid <algorithm> public key
    payload.accountId is not the SHA-256 of key1 + postQuantumKey1
    payload.transactionId is not the SHA-256 of the eight public keys in order

A transfer of one of the five types. `<field>` is `accountId`,
`transactionId`, `previousTransactionId`, `amount`, `accountIdTo` or
`createdAt`.

    payload.<field> must be a string
    payload.accountId is not a SHA-256 digest
    payload.accountIdTo is not a SHA-256 digest
    payload.previousTransactionId is not a SHA-256 digest
    payload.amount must be a positive integer (millionths of a unit) as a decimal string
    payload.transactionId is not the SHA-256 of the canonical payload without transactionId

A `transferToFund`: the same, with `stakeFor` among the fields that must
be strings, and before the `transactionId` line:

    payload.accountIdTo is not the fund
    payload.stakeFor must be one of daoVote, moderator, attestor, guardian, validator, masterPod

A `fundProposal`. `<field>` is `accountId`, `guardianId`, `createdAt` or
`transactionId`; `<i>` is a payout's place in `payouts`, from 0.

    payload.<field> must be a string
    payload.payouts must be an array with at least one payout
    payload.payouts[<i>] must be an object
    payload.payouts[<i>].accountIdTo must be a string
    payload.payouts[<i>].amount must be a string
    payload.payouts[<i>].reason must be a string
    payload.payouts[<i>].stakeFor must be a string when present
    payload.accountId is not a SHA-256 digest
    payload.accountId is not the fund
    payload.guardianId is not a SHA-256 digest
    payload.transactionId is not the SHA-256 of the canonical payload without transactionId
    payload.payouts[<i>].accountIdTo is not a SHA-256 digest
    payload.payouts[<i>].accountIdTo is the fund
    payload.payouts[<i>].amount must be a positive integer (millionths of a unit) as a decimal string
    payload.payouts[<i>].stakeFor must be one of daoVote, moderator, attestor, guardian, validator, masterPod

A follow-up. `<signer field>` is the kind's. A follow-up has no id of its
own. The fourth line is an `attestation`'s, the fifth a `guardianVote`'s,
the sixth an `escrowVerdict`'s.

    payload.transactionId must be a string
    payload.<signer field> must be a string
    payload.signedAt must be a string
    payload.accountId must be a string
    payload.vote must be "for" or "against"
    payload.verdict must be "success" or "cancel"
    payload.transactionId is not a SHA-256 digest
    payload.<signer field> is not a SHA-256 digest

The fund's account id is the SHA-256 of `anosFund`,
`b8f8da9cc80161e0705943de93dedfe850f0cab74b1939df806972df6ef61e24`.

Not copied, because it needs a database, a clock or a peer: that an
account exists, its type, its balance, the previous transaction, the
receiver, a date's distance from now, a stake, an appointment, a held
row. The validators check those.

**3. The creation.** For an `accountCreation` it is the transaction
itself. For every other kind, `creation.payload.publicKeys` must hold
`key1`, `postQuantumKey1`, `walletKey` and `walletPostQuantumKey` as
strings that decode for their algorithms. Nothing else of the creation is
read, and its own signatures are not checked: checks (a) and (c) tie the
request to the holder of pair one whatever else the creation says.

    creation is missing: send the signer account's creation with the request
    creation.payload.publicKeys.<name> must be a string
    creation.payload.publicKeys.<name> is not a valid <algorithm> public key

**4. Check (a).** The SHA-256 of the creation's `key1` and
`postQuantumKey1` strings, joined as sent, is the signer's account id: the
value of the kind's signer field, compared as bytes. For an
`accountCreation` this is the `accountId` line of step 2.

    payload.<signer field> is not the SHA-256 of the creation's key1 + postQuantumKey1

**5. Check (b).** The creation's two wallet keys are the two public keys
of one of this server's pairs, compared as bytes; both must belong to the
same pair. That pair signs. The P-256 key is compared in its 33-byte
compressed form, the form `GET /public-keys` answers.

    the creation's wallet key is not one of this server's

**6. Check (c).** Over the canonical bytes of the payload. An
`accountCreation`: each of the six signatures of the keys the browser
holds decodes and verifies against its key in the payload. Everything
else: `signatures.key1` and `signatures.postQuantumKey1` are both there,
and each decodes and verifies against the creation's key. Pair two's
signatures are not looked at, so a request signed by pair two alone is
refused. The first line is for everything but an `accountCreation`. The
third line is an `accountCreation`'s and the fourth everything else's;
those two are the validators' words.

    signatures.key1 and signatures.postQuantumKey1 must both be present
    signatures.<name> is not a valid <algorithm> signature
    signatures.<name> does not verify against payload.publicKeys.<name>
    signatures.<name> does not verify against the account's <name>

**7. The pair signs.** The one reason answered with `503`:

    kms unavailable

A holder of pair one can have any of this server's pairs sign for their
own account, by sending a creation that names another of its pairs. That
gains nothing: the validators verify against the pair the account's own
creation named, and refuse it.

## The 16 kinds

Eight are told apart by `payload.transactionType` and eight by
`payload.type`. The signer is not always the account in `accountId`.

| Kind | Told apart by | The signer's account id is |
| ---- | ------------- | -------------------------- |
| `accountCreation` | `payload.transactionType` | `payload.accountId`; the six browser keys sign |
| `anosTransfer`, `guardedAnosTransfer`, `vaultAnosTransfer`, `assistedAnosTransfer`, `escrowTransfer` | `payload.transactionType` | `payload.accountId` |
| `transferToFund` | `payload.transactionType` | `payload.accountId` |
| `fundProposal` | `payload.transactionType` | `payload.guardianId` (`accountId` is the fund) |
| `attestation` | `payload.type` | `payload.attestorId` |
| `assistedTransferCancel` | `payload.type` | `payload.accountId` |
| `lockedTransferCancel` | `payload.type` | `payload.accountId` |
| `guardianVote` | `payload.type` | `payload.guardianId` |
| `escrowSuccess`, `escrowCancel`, `escrowDispute` | `payload.type` | `payload.accountId` |
| `escrowVerdict` | `payload.type` | `payload.arbitratorId` |

A `breakGlassTransfer` and a `breakGlassCancel` never come here: the
break-glass pair signs them alone, and a validator refuses a wallet
pair's signature beside it.

## The pairs

A pair has one shape in both key stores (`src/pairs.js`): its `number`,
from 1; `walletKey` and `walletPostQuantumKey`, its two public keys in
hex, as `GET /public-keys` answers them; and `sign(message)`, which gives
the two signatures, 64 and 4627 bytes.

In the `local` key store the one pair signs with the two private keys of
`keys.json`.

In the `kms` key store the pairs are the ones listed in
`network/wallet-pairs.json`, which the key ceremony writes and which is
committed:

```
{
  "about": "...",
  "keyRing": "projects/signerkeys/locations/europe/keyRings/wallet-pairs",
  "pairs": [
    {
      "number": 1,
      "walletKey": "<66 hex characters, the compressed P-256 point>",
      "walletPostQuantumKey": "<5184 hex characters>",
      "walletKeyVersion": "projects/signerkeys/locations/europe/keyRings/wallet-pairs/cryptoKeys/pair-001-p256/cryptoKeyVersions/1",
      "walletPostQuantumKeyVersion": "projects/signerkeys/locations/europe/keyRings/wallet-pairs/cryptoKeys/pair-001-mldsa/cryptoKeyVersions/1"
    }
  ]
}
```

Every version name is the full name of a key version in Google. A key's
name carries the pair's number in three digits. `keyRing` is there for
the reader, and every version name must begin with it. The server does
not start, and says why, on:

- a file that is missing or not JSON;
- an empty `pairs`;
- a number that is not a positive integer, or comes twice;
- a public key of the wrong length for its algorithm, or one that comes
  twice;
- a version name that is not `keyRing` followed by
  `/cryptoKeys/<name>/cryptoKeyVersions/<number>`.

The count is what the file holds: the server does not ask for a fixed
number of pairs, and the numbers may have gaps.

A signature by a pair of the `kms` key store:

- The server asks Google Cloud KMS for both signatures at once
  (`src/kms.js`, with `@google-cloud/kms`, signed in as the machine
  itself, with no key file). The P-256 key is asked with the SHA-256 of
  the message; the ML-DSA-87 key with the message itself.
- Google answers the P-256 signature in DER form. The server turns it
  into the 64 bytes r‖s (`src/crypto/der.js`), the form the `local` key
  store gives.
- Both get 10 seconds together.
- Then both are verified against the pair's public keys, with the
  validators' verify, before anything is answered.
- No answer in time, an error from Google, or a signature that does not
  verify: the request is answered `503`.

## The boot check

At every boot, before the server listens, each pair signs a fixed message,
one pair after the other, and both signatures are verified against the
pair's public keys. In the `kms` key store that is one round with Google
per pair, so the server listens some seconds after it starts.

The boot lines, in the `local` key store (the first line reads
`keys.json written: a new wallet pair` at the first boot):

```
keys.json loaded
walletKey            <the pair's key, hex>
walletPostQuantumKey <the pair's key, hex>
key store local: 1 wallet pair
boot check: 1 pair signs and verifies
signingserver listening on http://localhost:3300
```

In the `kms` key store, with the count the list holds:

```
key store kms: 100 wallet pairs from network/wallet-pairs.json
boot check: 100 pairs sign and verify
signingserver listening on http://127.0.0.1:8300
```

The first pair that fails ends the boot: the server logs
`boot check failed: pair <number>: <reason>` and exits with 1, and
nothing listens.

## What is logged

After the boot lines, one line per signature and one per refusal:

```
signed <kind> for <signer> with pair <number>
refused: <reason>
kms unavailable: pair <number>: <what went wrong>
```

`<kind>` is one of the 16 names and `<signer>` the signer's account id
in hex, as the server decoded it, so no line carries text the sender
chose. No payload and no signature is logged. A body that is not JSON is
answered `400` and not logged.

## Layout

```
src/
  server.js              boots: the settings, the pairs, the boot check, listens
  config.js              the three settings: KEY_STORE, PORT, HOST
  app.js                 createApp(config, pairs): the four routes, the log lines, 404, the error handler
  pairs.js               the pairs of both key stores, the list's loader, findPair, randomPair, bootCheck
  keys.js                keys.json: make at first boot, load and check at every boot
  kms.js                 the one call to Google Cloud KMS
  sign.js                signRequest(body, pairs): the checks in order, then the two signatures
  checks/kinds.js        the 16 kinds, their families and signer fields, kindOf
  checks/creation.js     the shape and ids of a creation (copied from anossoftware)
  checks/transfers.js    the shape and ids of a transfer, a transferToFund, a fundProposal (copied from anossoftware)
  checks/follow-ups.js   the shape and ids of a follow-up (copied from anossoftware)
  crypto/canonical.js    RFC 8785 canonical JSON (copy of anossoftware's)
  crypto/signatures.js   P-256 and ML-DSA-87 (anossoftware's, with the ML-DSA-87 sign added)
  crypto/hash.js         SHA-256 helpers canonical.js imports (copy of anossoftware's)
  crypto/bytes.js        hex / base64 decoding signatures.js imports (copy of anossoftware's)
  crypto/der.js          a DER P-256 signature into the 64 bytes r‖s
network/
  wallet-pairs.json      the pairs of the kms key store, written by the key ceremony
```
