// The KMS try, second part: HPKE Seal by hand, with node:crypto only.
//
// Cloud KMS takes a post-quantum key only through its quantum-safe import
// methods, and during Preview the key has to be wrapped before it is sent.
// The wrap is HPKE Seal in base mode (RFC 9180, sections 5.1 and 5.2):
//
//   1. Encap: ML-KEM.Encaps to the import job's public key gives a 32-byte
//      shared secret and the encapsulation `enc` (draft-ietf-hpke-pq-05,
//      section 3: Encap is ML-KEM.Encaps itself, nothing is added).
//   2. KeySchedule: HKDF-SHA256 with the labels of RFC 9180 turns the shared
//      secret into an AES-256 key and a 12-byte nonce.
//   3. Seal: AES-256-GCM over the key file, sequence number 0.
//   4. The wrapped key is enc followed by the ciphertext and its 16-byte tag.
//
// The ids: KEM 0x0041 for ML-KEM-768 and 0x0042 for ML-KEM-1024 (the draft's
// table and Tink's hpke.go agree), KDF 0x0001, AEAD 0x0002 (RFC 9180,
// section 7). info and aad are empty: Google's sample calls Tink's
// Encrypt(targetKey, nil), and Tink passes that nil as info and seals with
// empty associated data.
//
// second-prove.mjs checks this file against published test vectors.

import { createCipheriv, createDecipheriv, createHmac, createPublicKey, decapsulate, encapsulate } from 'node:crypto';

/** The KEMs of the import methods: HPKE id, sizes in bytes, and the last byte of the key's OID 2.16.840.1.101.3.4.4.x. */
export const KEMS = {
  'ml-kem-768': { id: 0x0041, publicKeyBytes: 1184, encBytes: 1088, oidLast: 0x02 },
  'ml-kem-1024': { id: 0x0042, publicKeyBytes: 1568, encBytes: 1568, oidLast: 0x03 },
};

/** HPKE KDFs by id (RFC 9180, table 3). The import methods use 0x0001; the others are here for the test vectors. */
export const KDFS = {
  0x0001: { id: 0x0001, hash: 'sha256' },
  0x0002: { id: 0x0002, hash: 'sha384' },
  0x0003: { id: 0x0003, hash: 'sha512' },
};

/** HPKE AEADs by id (RFC 9180, table 5). The import methods use 0x0002; 0x0001 is here for the test vectors. */
export const AEADS = {
  0x0001: { id: 0x0001, cipher: 'aes-128-gcm', keyBytes: 16, nonceBytes: 12 },
  0x0002: { id: 0x0002, cipher: 'aes-256-gcm', keyBytes: 32, nonceBytes: 12 },
};

const TAG_BYTES = 16;
const EMPTY = Buffer.alloc(0);
const MODE_BASE = 0x00;

/** I2OSP(n, 2): a number as two bytes, big end first. */
const twoBytes = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);

/** HKDF-Extract (RFC 5869): HMAC with the salt as key. An empty salt is the same as a salt of zero bytes. */
function extract(hash, salt, ikm) {
  return createHmac(hash, salt).update(ikm).digest();
}

/** HKDF-Expand (RFC 5869). */
function expand(hash, prk, info, length) {
  const blocks = [];
  let block = EMPTY;
  for (let counter = 1, have = 0; have < length; counter++) {
    block = createHmac(hash, prk).update(block).update(info).update(Buffer.from([counter])).digest();
    blocks.push(block);
    have += block.length;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** LabeledExtract of RFC 9180, section 4. */
function labeledExtract(hash, suiteId, salt, label, ikm) {
  return extract(hash, salt, Buffer.concat([Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), ikm]));
}

/** LabeledExpand of RFC 9180, section 4. */
function labeledExpand(hash, suiteId, prk, label, info, length) {
  return expand(hash, prk, Buffer.concat([twoBytes(length), Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), info]), length);
}

/**
 * KeySchedule of RFC 9180, section 5.1, in base mode (no pre-shared key).
 * Returns the AEAD key and the base nonce; the context and the secret come
 * along so the proof can compare them with the RFC's values.
 */
export function keySchedule(kemId, kdfId, aeadId, sharedSecret, info = EMPTY) {
  const kdf = KDFS[kdfId];
  const aead = AEADS[aeadId];
  if (!kdf || !aead) throw new Error(`no such KDF or AEAD: ${kdfId}, ${aeadId}`);
  const suiteId = Buffer.concat([Buffer.from('HPKE'), twoBytes(kemId), twoBytes(kdfId), twoBytes(aeadId)]);
  const pskIdHash = labeledExtract(kdf.hash, suiteId, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = labeledExtract(kdf.hash, suiteId, EMPTY, 'info_hash', info);
  const context = Buffer.concat([Buffer.from([MODE_BASE]), pskIdHash, infoHash]);
  const secret = labeledExtract(kdf.hash, suiteId, sharedSecret, 'secret', EMPTY);
  const key = labeledExpand(kdf.hash, suiteId, secret, 'key', context, aead.keyBytes);
  const baseNonce = labeledExpand(kdf.hash, suiteId, secret, 'base_nonce', context, aead.nonceBytes);
  return { key, baseNonce, context, secret };
}

/** AEAD Seal: the ciphertext followed by the 16-byte tag. */
export function aeadSeal(aeadId, key, nonce, aad, plaintext) {
  const cipher = createCipheriv(AEADS[aeadId].cipher, key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

/** AEAD Open: the plaintext; throws when the key, the nonce, the aad or a byte of the ciphertext is wrong. */
export function aeadOpen(aeadId, key, nonce, aad, sealed) {
  if (sealed.length < TAG_BYTES) throw new Error('too short to hold a tag');
  const decipher = createDecipheriv(AEADS[aeadId].cipher, key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES));
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - TAG_BYTES)), decipher.final()]);
}

/** DER: a tag, the length, the content. */
function der(tag, content) {
  const n = content.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), content]);
}

/**
 * An ML-KEM public key for node:crypto from its raw bytes (the encapsulation
 * key of FIPS 203, which is what HPKE calls the serialized public key). The
 * raw bytes are put into the SubjectPublicKeyInfo form node reads.
 */
export function mlKemPublicKey(kemName, raw) {
  const kem = KEMS[kemName];
  if (!kem) throw new Error(`no such KEM: ${kemName}`);
  if (raw.length !== kem.publicKeyBytes) {
    throw new Error(`a ${kemName} public key is ${kem.publicKeyBytes} bytes, this one is ${raw.length}`);
  }
  const algorithm = der(0x30, der(0x06, Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, kem.oidLast])));
  const spki = der(0x30, Buffer.concat([algorithm, der(0x03, Buffer.concat([Buffer.from([0x00]), raw]))]));
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * HPKE Seal in one go, as a quantum-safe import job wants it: KEM `kemName`,
 * HKDF-SHA256, AES-256-GCM, base mode, empty info, empty aad. Returns enc
 * followed by the ciphertext and its tag. A fresh encapsulation is made on
 * every call, so two wraps of the same file differ.
 */
export function sealForImportJob(kemName, rawPublicKey, plaintext) {
  const kem = KEMS[kemName];
  const { sharedKey, ciphertext: enc } = encapsulate(mlKemPublicKey(kemName, rawPublicKey));
  if (sharedKey.length !== 32 || enc.length !== kem.encBytes) {
    throw new Error(`${kemName} gave a ${sharedKey.length}-byte secret and a ${enc.length}-byte encapsulation`);
  }
  const { key, baseNonce } = keySchedule(kem.id, 0x0001, 0x0002, sharedKey, EMPTY);
  // Sequence number 0, so the nonce is the base nonce itself.
  const sealed = aeadSeal(0x0002, key, baseNonce, EMPTY, plaintext);
  sharedKey.fill(0);
  key.fill(0);
  return Buffer.concat([enc, sealed]);
}

/**
 * The other side, for the proof only: what the import job does with a
 * wrapped key. `privateKey` is a node:crypto ML-KEM private key.
 */
export function openAsImportJob(kemName, privateKey, wrapped) {
  const kem = KEMS[kemName];
  if (wrapped.length < kem.encBytes + TAG_BYTES) throw new Error('too short to be a wrapped key');
  const sharedSecret = decapsulate(privateKey, wrapped.subarray(0, kem.encBytes));
  const { key, baseNonce } = keySchedule(kem.id, 0x0001, 0x0002, sharedSecret, EMPTY);
  return aeadOpen(0x0002, key, baseNonce, EMPTY, wrapped.subarray(kem.encBytes));
}
