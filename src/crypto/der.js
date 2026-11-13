/**
 * An ECDSA P-256 signature out of its DER form. Google Cloud KMS answers a
 * P-256 signature as DER, SEQUENCE { INTEGER r, INTEGER s }, 70 to 72 bytes
 * as a rule. The wallet gets the 64 bytes r || s (IEEE P1363) from this
 * server, in both key stores, so the answer from Google is turned into
 * them here.
 */

const SEQUENCE = 0x30;
const INTEGER = 0x02;

/** The bytes of r and of s in the 64-byte form. */
const HALF_BYTES = 32;

/**
 * The 64 bytes r || s of a DER signature (a Buffer or a Uint8Array): the
 * leading zero byte of each integer is cut and each is padded on the left
 * to 32 bytes. Throws on anything that is not a sequence of exactly two
 * integers, or whose integers are longer than 32 bytes.
 */
export function derToRaw(signature) {
  if (!(signature instanceof Uint8Array)) throw new TypeError('not a DER signature: not bytes');
  const der = Buffer.from(signature);

  // Two integers of at most 33 bytes each never need more than a one-byte
  // length, and nothing may follow the sequence.
  if (der.length < 2 || der[0] !== SEQUENCE || der[1] >= 0x80 || der[1] !== der.length - 2) {
    throw new Error('not a DER signature: no sequence of that length');
  }
  const r = readInteger(der, 2);
  const s = readInteger(der, r.end);
  if (s.end !== der.length) throw new Error('not a DER signature: more than two integers');
  return Buffer.concat([pad(r.value), pad(s.value)]);
}

/** The integer that starts at `at`: { value, end }, the value without its leading zero byte. */
function readInteger(der, at) {
  if (at + 2 > der.length || der[at] !== INTEGER) throw new Error('not a DER signature: an integer is missing');
  const length = der[at + 1];
  const end = at + 2 + length;
  if (length === 0 || length >= 0x80 || end > der.length) {
    throw new Error('not a DER signature: an integer has a bad length');
  }
  let value = der.subarray(at + 2, end);
  if (value[0] >= 0x80) throw new Error('not a DER signature: an integer is negative');
  // DER puts a zero byte in front of an integer whose first bit is set.
  if (value.length > 1 && value[0] === 0x00) value = value.subarray(1);
  if (value.length > HALF_BYTES) throw new Error('not a P-256 signature: an integer is longer than 32 bytes');
  return { value, end };
}

function pad(value) {
  return Buffer.concat([Buffer.alloc(HALF_BYTES - value.length), value]);
}
