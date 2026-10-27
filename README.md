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
