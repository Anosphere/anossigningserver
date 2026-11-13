// The KMS try, third part: the RSA wrap by hand, with node:crypto only.
//
// A P-256 key cannot come in through a quantum-safe import job (the second
// try), so it comes in through an RSA one, import method
// rsa-oaep-3072-sha256-aes-256. In the first try gcloud did this wrap inside
// Cloud Shell; in the real key ceremony it has to happen on the Mac. Google's
// page "Wrapping a key using OpenSSL on Linux" gives the steps:
//
//   1. A fresh random 32-byte AES key.
//   2. That AES key wrapped with the import job's RSA public key: RSA-OAEP
//      with SHA-256, MGF1 with SHA-256, empty label. 384 bytes for RSA-3072.
//   3. The key file wrapped with the AES key: AES key wrap with padding,
//      RFC 5649, which OpenSSL calls id-aes256-wrap-pad, with the RFC's
//      initial value A65959A6.
//   4. The wrapped key is the wrapped AES key followed by the wrapped file.
//
// third-prove.mjs checks this file against published test vectors and
// against the OpenSSL commands of Google's page.

import { constants, createCipheriv, createDecipheriv, createPublicKey, privateDecrypt, publicEncrypt, randomBytes } from 'node:crypto';

/** The first four bytes of the initial value of RFC 5649, section 3. */
const KWP_INITIAL_VALUE = Buffer.from('a65959a6', 'hex');

/** AES key wrap with padding (RFC 5649) of `data` under the key `kek` (16, 24 or 32 bytes). */
export function aesKeyWrapPad(kek, data) {
  const cipher = createCipheriv(`id-aes${kek.length * 8}-wrap-pad`, kek, KWP_INITIAL_VALUE);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/** The other way, for the proof only; throws when the key or a byte of the wrap is wrong. */
export function aesKeyUnwrapPad(kek, wrapped) {
  const decipher = createDecipheriv(`id-aes${kek.length * 8}-wrap-pad`, kek, KWP_INITIAL_VALUE);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}

/** RSA-OAEP with SHA-256 for the padding and for MGF1, empty label. */
export function rsaOaepSha256(publicKey, data) {
  return publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, data);
}

/**
 * The import job's RSA public key from its PEM text. The import method
 * names the size, so a key of another kind or size is refused here.
 */
export function importJobRsaKey(pem, bits = 3072) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'rsa') throw new Error(`the import job's key is ${key.asymmetricKeyType}, not rsa`);
  const found = key.asymmetricKeyDetails?.modulusLength;
  if (found !== bits) throw new Error(`the import job's RSA key is ${found} bits, not ${bits}`);
  return key;
}

/**
 * The wrap for an import job with the method rsa-oaep-3072-sha256-aes-256:
 * the wrapped AES key, then the wrapped key file. A fresh AES key is made
 * on every call, so two wraps of the same file differ.
 */
export function wrapForRsaImportJob(publicKey, plaintext) {
  const aesKey = randomBytes(32);
  const wrappedAesKey = rsaOaepSha256(publicKey, aesKey);
  const wrappedFile = aesKeyWrapPad(aesKey, plaintext);
  aesKey.fill(0);
  return Buffer.concat([wrappedAesKey, wrappedFile]);
}

/** The other side, for the proof only: what the import job does with a wrapped key. */
export function openAsRsaImportJob(privateKey, wrapped) {
  const rsaBytes = privateKey.asymmetricKeyDetails.modulusLength / 8;
  if (wrapped.length <= rsaBytes) throw new Error('too short to be a wrapped key');
  const aesKey = privateDecrypt(
    { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    wrapped.subarray(0, rsaBytes),
  );
  return aesKeyUnwrapPad(aesKey, wrapped.subarray(rsaBytes));
}
