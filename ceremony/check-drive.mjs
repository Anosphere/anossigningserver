#!/usr/bin/env node
// The key ceremony's drive check, on the Mac, at any time (ceremony/README.md).
//
//   node check-drive.mjs <folder>
//
// Checks the folder of wallet pairs on an encrypted drive, with the
// network off: the script stops while the Mac has a network address that
// is neither internal nor link-local, as make-pairs.mjs does. For every
// pair in the folder:
//
//   - both key files have their size and their framing,
//   - each gives the public key the folder's public.json names, and signs
//     for it,
//   - the checksums of SHA256SUMS hold.
//
// When the repo's list of pairs, network/wallet-pairs.json, is beside this
// script's folder, every pair of the list must be in the folder with the
// same public keys. A pair of the folder that the list does not hold is
// named `not in the list` and is no failure: it is a pair that was left
// out because it was not good in Google. Run from a drive's own copy, in
// code/ceremony/, there is no list beside it and the folder is checked
// against its own public.json alone.
//
// It prints one line per pair, `good` or `NOT GOOD` with what failed, then
// `<n> of <m> pairs good`. It reads the key files and writes nothing, and
// it prints names and sizes, never a byte of a private key.

import { ECDH, createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** The list of pairs in the repo, when this script runs from the repo. */
const LIST = resolve(here, '..', 'network', 'wallet-pairs.json');

/**
 * The two halves of a pair, as in make-pairs.mjs. Per half: its name in a
 * file name, its name in public.json and in the list of pairs, the size
 * of its key file, and the framing: the fixed bytes of the key file around
 * the secret, each with its place. A P-256 key file is the PKCS #8 file of
 * 138 bytes: 36 bytes, the 32-byte secret, 6 bytes, then the two halves of
 * the public point. An ML-DSA-87 key file is the PKCS #8 file of 54 bytes
 * that holds the seed alone: 22 bytes, then the 32-byte seed.
 */
const HALVES = [
  {
    half: 'p256',
    field: 'walletKey',
    fileBytes: 138,
    framing: [[0, '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420'], [68, 'a14403420004']],
  },
  {
    half: 'mldsa',
    field: 'walletPostQuantumKey',
    fileBytes: 54,
    framing: [[0, '3034020100300b060960864801650304031304228020']],
  },
];

/** What is signed to see that a key file signs for its own public key. */
const SELF_TEST = Buffer.from('the key ceremony of the wallet pairs: a key file signs for its public key', 'utf8');

const KEY_FILE = /^pair-(\d{3})-(p256|mldsa)\.der$/;

/** A pair's number in three digits, as every name carries it. */
const three = (number) => String(number).padStart(3, '0');

/** The name of a key file on a drive. */
const keyFile = (number, half) => `pair-${three(number)}-${half}.der`;

const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');

/** Ends the run with the reason. */
function stop(reason) {
  console.log(`Stopped: ${reason}`);
  process.exit(1);
}

/** The Mac's network addresses that are neither internal nor link-local, each with its interface. None when the network is off. */
function networkAddresses() {
  const found = [];
  for (const [name, addresses] of Object.entries(networkInterfaces())) {
    for (const { address, family, internal } of addresses ?? []) {
      if (internal) continue;
      if (family === 'IPv4' && address.startsWith('169.254.')) continue;
      if (family === 'IPv6' && /^fe[89ab][0-9a-f]:/i.test(address)) continue;
      found.push(`${name} ${address}`);
    }
  }
  return found;
}

/**
 * The public key of a key file, as the raw bytes a creation carries: the
 * 33-byte compressed point for a P-256 key, the 2592 bytes for an
 * ML-DSA-87 key. Before that the file's size and framing are checked, and
 * the key signs once and the signature is verified against the public
 * key, so a file whose secret and public halves do not belong together is
 * caught. Throws with what is wrong, worded to follow the file's name.
 */
function publicKeyOf(half, der) {
  const { fileBytes, framing } = HALVES.find((entry) => entry.half === half);
  if (der.length !== fileBytes) throw new Error(`is ${der.length} bytes, not ${fileBytes}`);
  for (const [at, hex] of framing) {
    const fixed = Buffer.from(hex, 'hex');
    if (!der.subarray(at, at + fixed.length).equals(fixed)) throw new Error('does not have the framing of a key file');
  }
  let privateKey;
  let publicKey;
  try {
    privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    publicKey = createPublicKey(privateKey);
  } catch {
    throw new Error('is not a key that can be read');
  }
  const digest = half === 'p256' ? 'sha256' : null;
  if (!verify(digest, SELF_TEST, publicKey, sign(digest, SELF_TEST, privateKey))) {
    throw new Error('does not sign for its own public key');
  }
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  if (half === 'p256') {
    return Buffer.from(ECDH.convertKey(spki.subarray(spki.length - 65), 'prime256v1', undefined, undefined, 'compressed'));
  }
  return Buffer.from(spki.subarray(spki.length - 2592));
}

/** The pairs a JSON file names, by number: public.json of a folder, or the repo's list. Throws when it is not such a file. */
function namedPairs(path) {
  const { pairs } = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(pairs)) throw new Error('it has no pairs');
  const named = new Map();
  for (const pair of pairs) {
    if (!Number.isSafeInteger(pair?.number) || HALVES.some(({ field }) => typeof pair[field] !== 'string')) {
      throw new Error('one of its pairs has no number or no public key');
    }
    named.set(pair.number, pair);
  }
  return named;
}

// --- the run -------------------------------------------------------------------------

if (process.argv.length !== 3 || process.argv[2].startsWith('--')) {
  console.log('Give the folder of wallet pairs on the drive:\n\n  node check-drive.mjs <folder>');
  process.exit(1);
}
const folder = resolve(process.argv[2]);
console.log(`The drive check: ${folder}`);

const addresses = networkAddresses();
if (addresses.length > 0) {
  stop(`the network is on (${addresses.join(', ')}). Switch Wi-Fi off and pull the cable, then run this line again.`);
}
console.log('The network: off.');

if (!existsSync(folder) || !statSync(folder).isDirectory()) stop(`${folder} is not a folder. Is the drive plugged in and unlocked?`);

// What the folder says of itself: its public keys and its checksums.
let named;
try {
  named = namedPairs(join(folder, 'public.json'));
} catch (error) {
  stop(`${join(folder, 'public.json')} is unusable: ${error.code === 'ENOENT' ? 'it is not there' : error.message}.`);
}
const sums = new Map();
try {
  for (const line of readFileSync(join(folder, 'SHA256SUMS'), 'utf8').split('\n')) {
    if (line === '') continue;
    const match = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
    if (match === null) throw new Error('one of its lines is not a checksum and a name');
    sums.set(match[2], match[1]);
  }
} catch (error) {
  stop(`${join(folder, 'SHA256SUMS')} is unusable: ${error.code === 'ENOENT' ? 'it is not there' : error.message}.`);
}

// The repo's list, when this script runs from the repo.
let list = null;
if (existsSync(LIST)) {
  try {
    list = namedPairs(LIST);
  } catch (error) {
    stop(`${LIST} is unusable: ${error.message}.`);
  }
  console.log(`The list of pairs: ${LIST}, ${list.size} pairs`);
} else {
  console.log('The list of pairs: none beside this script, so the folder is checked against its own public.json alone.');
}

// The key files that are there, by pair.
const there = new Map();
let names;
try {
  names = readdirSync(folder);
} catch (error) {
  stop(`${folder} could not be read (${error.code ?? error.message}). When macOS asks whether Terminal may reach files on a removable volume, the answer is yes.`);
}
for (const name of names) {
  const match = KEY_FILE.exec(name);
  if (match === null) continue;
  const number = Number(match[1]);
  there.set(number, (there.get(number) ?? new Set()).add(match[2]));
}

// One line per pair: every pair the folder holds, public.json names or the list names.
const numbers = [...new Set([...there.keys(), ...named.keys(), ...(list?.keys() ?? [])])].sort((a, b) => a - b);
let good = 0;
for (const number of numbers) {
  const problems = [];
  if (!there.has(number)) {
    problems.push(list?.has(number) ? 'the list names it and this folder does not hold it' : 'public.json names it and its key files are not here');
  } else if (!named.has(number)) {
    problems.push('public.json does not name it');
  } else {
    for (const { half, field } of HALVES) {
      const name = keyFile(number, half);
      if (!there.get(number).has(half)) {
        problems.push(`${name} is missing`);
        continue;
      }
      const der = readFileSync(join(folder, name));
      if (!sums.has(name)) problems.push(`${name} is not in SHA256SUMS`);
      else if (sums.get(name) !== sha256Hex(der)) problems.push(`${name} does not have its checksum`);
      let publicKey = null;
      try {
        publicKey = publicKeyOf(half, der).toString('hex');
      } catch (error) {
        problems.push(`${name} ${error.message}`);
      }
      der.fill(0);
      if (publicKey === null) continue;
      if (named.get(number)[field].toLowerCase() !== publicKey) problems.push(`${name} does not give the public key public.json names`);
      if (list?.has(number) && list.get(number)[field].toLowerCase() !== publicKey) problems.push(`${name} does not give the public key the list names`);
    }
  }
  if (problems.length === 0) good += 1;
  console.log(problems.length === 0
    ? `pair ${three(number)}: good${list !== null && !list.has(number) ? ', not in the list' : ''}`
    : `pair ${three(number)}: NOT GOOD: ${problems.join('; ')}`);
}

// What is not a pair's: public.json's own checksum, and checksums of files that are gone.
const other = [];
if (!sums.has('public.json')) other.push('public.json is not in SHA256SUMS');
else if (sums.get('public.json') !== sha256Hex(readFileSync(join(folder, 'public.json')))) other.push('public.json does not have its checksum');
for (const name of sums.keys()) {
  if (name !== 'public.json' && !existsSync(join(folder, name))) other.push(`SHA256SUMS names ${name}, which is not here`);
}
for (const line of other) console.log(`NOT GOOD: ${line}`);

console.log(`${good} of ${numbers.length} pairs good`);
if (other.length > 0) console.log(`The folder is NOT GOOD all the same: see the ${other.length === 1 ? 'line' : 'lines'} above the count.`);
process.exit(good === numbers.length && numbers.length > 0 && other.length === 0 ? 0 : 1);
