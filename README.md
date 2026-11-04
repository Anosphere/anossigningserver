# signingserver

The stand-in for the serversigner software: an Express 5 server that signs
whatever the wallet hands it with the wallet key pair and hands it back. No
database, no auth, no CORS (only the wallet's proxy calls it). The spec is
`~/Desktop/Z/web_app/docs/schemas.md` section 3.

## Running it

```bash
npm install
npm start          # PORT=3300 by default; npm run dev restarts on file changes
```

The first boot writes `keys.json` in the project root: a P-256 pair and an
ML-DSA-87 pair from `node:crypto`, private keys as PKCS#8 DER in hex, public
keys raw (the SPKI prefix cut): 33 bytes compressed and 2592 bytes. The file
is git-ignored. Every boot checks each private key against its public key and
logs the two public keys.

## On signing1

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
| `GET /health`       | `200 { status: "ok", uptime }` |
| `GET /public-keys`  | `200 { walletKey: hex (33 bytes), walletPostQuantumKey: hex (2592 bytes) }` |
| `POST /sign`        | body `{ transaction: { payload: object, signatures: object } }`; `200 { transaction }` with `signatures.walletKey` (64 bytes r‖s over the SHA-256 of the RFC 8785 canonical bytes of `payload`) and `signatures.walletPostQuantumKey` (4627 bytes, pure ML-DSA-87, empty context, over the canonical bytes) set, replacing any present, everything else untouched; `400 { error: "bad request shape" }` when `transaction`, `payload` or `signatures` is not an object |

JSON limit 1 MB (a creation is about 60 KB). Unknown path: `404 { error:
"Not Found", path }`. Nothing is logged but the boot lines.

## Layout

```
src/
  server.js              boots: loads or makes the keys, logs the public keys, listens
  app.js                 createApp(keys): the four routes, 404, the error handler
  keys.js                keys.json: make at first boot, load and check at every boot
  sign.js                signTransaction(body, privateKeys): the shape check and the two signatures
  crypto/canonical.js    RFC 8785 canonical JSON (copy of anossoftware's)
  crypto/signatures.js   P-256 and ML-DSA-87 (anossoftware's, with the ML-DSA-87 sign added)
  crypto/hash.js         SHA-256 helpers canonical.js imports (copy of anossoftware's)
  crypto/bytes.js        hex / base64 decoding signatures.js imports (copy of anossoftware's)
```
