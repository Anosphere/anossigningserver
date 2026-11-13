#!/usr/bin/env node
// The key ceremony, step 4 of 4, on the Mac (ceremony/README.md).
//
//   node check.mjs [--out-pack <pack>] [--work <folder>] [--write-list] [--pairs 100]
//
// Takes the out pack Cloud Shell made in step 3 and checks every pair of
// the run against what this Mac kept of it in the work folder. A pair is
// good when the two public keys Google holds are the ones this Mac made
// (the run's public.json) and both of Google's signatures of the short
// message pass verifySignature of ../src/crypto/signatures.js, the
// validators' own check. So a pair is good only when Google holds the very
// keys this Mac made and wrapped, and signs with them as a validator wants
// it. No private key is needed here: the network may be on and the drives
// stay in their places.
//
//   --out-pack    the out pack of step 3; when left out, the newest
//                 wallet-pairs-out-*.tgz in ~/Downloads
//   --work        the work folder, ~/Desktop/wallet-pairs-work when left
//                 out. The run is the one there with the pack's stamp.
//   --write-list  also write the list of pairs into the repo, as
//                 network/wallet-pairs.json, the file the signing server
//                 reads its pairs from
//   --pairs       how many good pairs --write-list asks for; 100 when left
//                 out
//
// It prints one line per pair, `good` or `NOT GOOD` with what failed, then
// `<n> of <m> pairs good`, then one line on the large message. It writes
// wallet-pairs.json into the run's work folder: the good pairs, each with
// the names of its two key versions in Google. A pair that is not good is
// left out. With --write-list it writes the same list into the repo, anew,
// when the key ring is wallet-pairs and at least --pairs pairs are good;
// with fewer it writes nothing there and says how many are missing.

import { execFileSync } from 'node:child_process';
import { ECDH, createPublicKey } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ECDSA_P256, ML_DSA_87, decodePublicKey, verifySignature } from '../src/crypto/signatures.js';

const here = dirname(fileURLToPath(import.meta.url));
const TAR = '/usr/bin/tar';

/** The key ring of the real wallet pairs. Only its list goes into the repo. */
const REAL_RING = 'wallet-pairs';

/** The list of pairs in the repo, which the signing server's kms key store reads (src/pairs.js). */
const LIST = resolve(here, '..', 'network', 'wallet-pairs.json');

/** The two halves of a pair: the algorithm as the manifest names it for Google, the validators' name for it, the half's name in public.json and in the list, and the length of its public key in hex. */
const HALVES = [
  { kmsAlgorithm: 'ec-sign-p256-sha256', algorithm: ECDSA_P256, field: 'walletKey', hexLength: 66 },
  { kmsAlgorithm: 'pq-sign-ml-dsa-87', algorithm: ML_DSA_87, field: 'walletPostQuantumKey', hexLength: 5184 },
];

const SAFE = /^[A-Za-z0-9._-]+$/;
const STAMP = /^\d{4}-\d{6}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const USAGE = '  node check.mjs [--out-pack <pack>] [--work <folder>] [--write-list] [--pairs 100]';

/** A pair's number in three digits, as every name carries it. */
const three = (number) => String(number).padStart(3, '0');

/** Ends the run with the reason. */
function stop(reason) {
  console.log(`Stopped: ${reason}`);
  process.exit(1);
}

/** Ends the run over a line that is not understood. */
function usage(reason) {
  console.log(`${reason}\n\n${USAGE}`);
  process.exit(1);
}

/** The words after `node check.mjs`. */
function readArguments(words) {
  const args = { outPack: null, work: join(homedir(), 'Desktop', 'wallet-pairs-work'), writeList: false, pairs: 100 };
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const value = () => {
      if (i + 1 >= words.length) usage(`${word} needs a value after it.`);
      return words[++i];
    };
    if (word === '--out-pack') args.outPack = resolve(value());
    else if (word === '--work') args.work = resolve(value());
    else if (word === '--write-list') args.writeList = true;
    else if (word === '--pairs') {
      const text = value();
      if (!/^[1-9][0-9]{0,2}$/.test(text)) usage(`--pairs takes a number from 1 to 999, not ${text}.`);
      args.pairs = Number(text);
    } else usage(`Not understood: ${word}`);
  }
  return args;
}

/** The newest file in ~/Downloads whose name starts with `start` and ends .tgz; null when there is none. */
function newestDownload(start) {
  const dir = join(homedir(), 'Downloads');
  if (!existsSync(dir)) return null;
  const found = readdirSync(dir)
    .filter((name) => name.startsWith(start) && name.endsWith('.tgz'))
    .map((name) => join(dir, name))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return found[0] ?? null;
}

/** ring.txt: the run's project, location, key ring, stamp and the time its import jobs were made. Throws on anything else. */
function readRing(text) {
  const ring = {};
  for (const line of text.split('\n')) {
    const [name, value, ...more] = line.trim().split(/\s+/);
    if (name === '') continue;
    if (value === undefined || more.length > 0) throw new Error('a line of ring.txt is not understood');
    ring[name] = value;
  }
  for (const [name, form] of [['project', SAFE], ['location', SAFE], ['ring', SAFE], ['stamp', STAMP], ['made', TIME]]) {
    if (typeof ring[name] !== 'string' || !form.test(ring[name])) throw new Error(`ring.txt has no usable ${name}`);
  }
  return ring;
}

/**
 * Opens the out pack of step 3 in the work folder: first its ring.txt
 * alone, read out of the pack, to learn the run; then, when the work
 * folder has that run, the whole pack into the run's folder, anew. The
 * pack is only read as data, and a pack that holds anything but plain
 * files in one folder wallet-pairs-out-<stamp> is refused. Returns the
 * pack's ring.txt, the run's folder and the unpacked folder.
 */
function openOutPack(pack, work) {
  let members;
  try {
    members = execFileSync(TAR, ['-tzf', pack], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
      .split('\n').filter((member) => member !== '').map((member) => member.replace(/^\.\//, ''));
  } catch {
    throw new Error('tar cannot read it');
  }
  const top = (members[0] ?? '').split('/')[0];
  if (!/^wallet-pairs-out-\d{4}-\d{6}$/.test(top)) throw new Error('it holds no folder wallet-pairs-out-<stamp>');
  for (const member of members) {
    const [folder, name, ...more] = member.split('/');
    if (folder !== top || more.length > 0 || (name !== undefined && name !== '' && !SAFE.test(name))) {
      throw new Error(`it holds something that is not a plain file of its folder: ${member.slice(0, 80)}`);
    }
  }
  if (!members.includes(`${top}/ring.txt`)) throw new Error('it holds no ring.txt');
  const ring = readRing(execFileSync(TAR, ['-xzOf', pack, `${top}/ring.txt`], { stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8'));
  if (top !== `wallet-pairs-out-${ring.stamp}`) throw new Error('its folder and its ring.txt name two different stamps');

  const run = join(work, ring.stamp);
  if (!existsSync(join(run, `wallet-pairs-wrapped-${ring.stamp}`, 'public.json'))) return { ring, run, out: null };
  const out = join(run, top);
  rmSync(out, { recursive: true, force: true });
  execFileSync(TAR, ['-xzf', pack, '-C', run], { stdio: ['ignore', 'pipe', 'pipe'] });
  return { ring, run, out };
}

/** The lines of a text file as lists of words; empty lines are left out. */
function wordLines(text) {
  return text.split('\n').map((line) => line.trim()).filter((line) => line !== '').map((line) => line.split(/\s+/));
}

/**
 * The public key Google holds for a key, out of the file gcloud wrote, as
 * the raw bytes a creation carries: 33 bytes for a P-256 key, 2592 for an
 * ML-DSA-87 key. gcloud writes a P-256 key as PEM text and an ML-DSA-87
 * key, asked for in the NIST form, as its 2592 bytes. The raw point, DER
 * and hex or base64 text are read too. Null for anything else.
 */
function publicKeyFromGoogle(algorithm, file) {
  if (file === null) return null;
  let raw = decodePublicKey(algorithm, file) ?? decodePublicKey(algorithm, file.toString('latin1').trim());
  if (raw === null && algorithm === ECDSA_P256) {
    for (const options of [{ key: file.toString('latin1'), format: 'pem' }, { key: file, format: 'der', type: 'spki' }]) {
      try {
        const key = createPublicKey(options);
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') continue;
        // The point is what follows the 26 bytes that name the algorithm and the curve.
        raw = decodePublicKey(algorithm, key.export({ format: 'der', type: 'spki' }).subarray(26));
        if (raw !== null) break;
      } catch {
        // not this form
      }
    }
  }
  if (raw === null) return null;
  return algorithm === ECDSA_P256 && raw.length === 65
    ? Buffer.from(ECDH.convertKey(raw, 'prime256v1', undefined, undefined, 'compressed'))
    : raw;
}

// --- the run -------------------------------------------------------------------------

const args = readArguments(process.argv.slice(2));

const pack = args.outPack ?? newestDownload('wallet-pairs-out-');
if (pack === null || !existsSync(pack)) {
  stop(`there is no out pack${pack ? ` at ${pack}` : ' in ~/Downloads'}. Download wallet-pairs-out-<stamp>.tgz from Cloud Shell first (step 3), or name it with --out-pack.`);
}
let ring;
let run;
let out;
try {
  ({ ring, run, out } = openOutPack(pack, args.work));
} catch (error) {
  stop(`the out pack is unusable: ${error.message}. The pack: ${pack}`);
}
const wrapped = join(run, `wallet-pairs-wrapped-${ring.stamp}`);
if (out === null) {
  stop(`the work folder has no run ${ring.stamp}: ${join(wrapped, 'public.json')} is not there. The out pack is of another run, or --work names another folder. The pack: ${pack}`);
}
console.log('The key ceremony, step 4 of 4: the check.');
console.log(`The out pack: ${pack}`);
console.log(`  run ${ring.stamp}: project ${ring.project}, location ${ring.location}, key ring ${ring.ring}`);
console.log(`The run on this Mac: ${run}`);

/** A file of the out pack, or null when Cloud Shell did not produce it. */
const got = (name) => (existsSync(join(out, name)) ? readFileSync(join(out, name)) : null);

// What this Mac kept of the run: the ring, the public keys, the key names, the two messages.
let mine;
let pairs;
let small;
let large;
const names = new Map();
try {
  mine = readRing(readFileSync(join(wrapped, 'ring.txt'), 'utf8'));
  pairs = JSON.parse(readFileSync(join(wrapped, 'public.json'), 'utf8')).pairs;
  if (!Array.isArray(pairs) || pairs.length === 0) throw new Error('public.json names no pair');
  for (const pair of pairs) {
    if (!Number.isSafeInteger(pair?.number) || pair.number < 1) throw new Error('public.json has a pair without a number');
    for (const { field, hexLength } of HALVES) {
      if (typeof pair[field] !== 'string' || pair[field].length !== hexLength || !/^[0-9a-f]+$/.test(pair[field])) {
        throw new Error(`public.json: pair ${three(pair.number)} has no usable ${field}`);
      }
    }
  }
  for (const [number, key, , kmsAlgorithm] of wordLines(readFileSync(join(wrapped, 'manifest.txt'), 'utf8'))) {
    const half = HALVES.find((entry) => entry.kmsAlgorithm === kmsAlgorithm);
    if (!/^[1-9][0-9]*$/.test(number) || !SAFE.test(key ?? '') || half === undefined) throw new Error('a line of manifest.txt is not understood');
    names.set(`${Number(number)} ${half.field}`, key);
  }
  small = readFileSync(join(wrapped, 'msg-small.txt'));
  large = readFileSync(join(wrapped, 'msg-large.bin'));
} catch (error) {
  stop(`the run in the work folder is unusable: ${error.message}. The folder: ${wrapped}`);
}
for (const field of ['project', 'location', 'ring', 'stamp']) {
  if (mine[field] !== ring[field]) stop(`the out pack and the run on this Mac do not name the same ${field}: ${ring[field]} and ${mine[field]}.`);
}

const keyRing = `projects/${ring.project}/locations/${ring.location}/keyRings/${ring.ring}`;

// Each key's ENABLED version, as Cloud Shell wrote it down: the key's name, then the version's full name.
const versions = new Map();
for (const [key, version] of wordLines((got('versions.txt') ?? Buffer.alloc(0)).toString('utf8'))) versions.set(key, version ?? '');

const count = (got('results.txt') ?? Buffer.alloc(0)).toString('utf8').split('\n').findLast((line) => line.startsWith('Brought in and ENABLED:'));
console.log(`Cloud Shell's last line: ${count ?? '(none in the pack)'}`);
console.log('');

// One line per pair.
const good = [];
for (const pair of pairs) {
  const problems = [];
  const entry = { number: pair.number, walletKey: pair.walletKey, walletPostQuantumKey: pair.walletPostQuantumKey };
  for (const { algorithm, field } of HALVES) {
    const key = names.get(`${pair.number} ${field}`);
    if (key === undefined) {
      problems.push(`the run's manifest names no ${algorithm} key for it`);
      continue;
    }
    const version = versions.get(key);
    if (version === undefined) {
      problems.push(`Google holds no ENABLED version of ${key}, or the out pack is of an older pack`);
      continue;
    }
    if (!version.startsWith(`${keyRing}/cryptoKeys/${key}/cryptoKeyVersions/`) || !/^[1-9][0-9]*$/.test(version.slice(version.lastIndexOf('/') + 1))) {
      problems.push(`the out pack names no usable version of ${key}`);
      continue;
    }
    entry[`${field}Version`] = version;

    const made = Buffer.from(pair[field], 'hex');
    const held = publicKeyFromGoogle(algorithm, got(`${key}.pub`));
    if (held === null) problems.push(`no public key of ${key} came back`);
    else if (!held.equals(made)) problems.push(`the public key Google holds for ${key} is not the one this Mac made`);

    const signature = got(`${key}.small.sig`);
    if (signature === null) problems.push(`no signature by ${key} came back`);
    else if (!verifySignature(algorithm, made, small, signature)) problems.push(`the signature by ${key} does not pass the validators' check`);
  }
  if (problems.length === 0) good.push(entry);
  console.log(problems.length === 0 ? `pair ${three(pair.number)}: good` : `pair ${three(pair.number)}: NOT GOOD: ${problems.join('; ')}`);
}
console.log(`${good.length} of ${pairs.length} pairs good`);

// The large message: the largest payload a validator would take, signed by the first ML-DSA-87 key that came in.
const bytes = large.length.toLocaleString('en-US');
const largeKey = wordLines((got('large.txt') ?? Buffer.alloc(0)).toString('utf8'))[0]?.[0];
const largeSignature = got('large.sig');
const signer = pairs.find((pair) => names.get(`${pair.number} walletPostQuantumKey`) === largeKey);
if (largeKey === undefined) {
  console.log(`The large message of ${bytes} bytes: not signed, because no ML-DSA-87 key came in.`);
} else if (largeSignature === null) {
  const answer = (got('large.err') ?? Buffer.alloc(0)).toString('utf8').replace(/\s+/g, ' ').trim().slice(0, 500);
  console.log(`The large message of ${bytes} bytes: Google refused it. Its answer: ${answer === '' ? '(none in the pack)' : answer}`);
} else if (signer !== undefined && verifySignature(ML_DSA_87, Buffer.from(signer.walletPostQuantumKey, 'hex'), large, largeSignature)) {
  console.log(`The large message of ${bytes} bytes: Google signed it with ${largeKey}, and the signature passes the validators' check.`);
} else {
  console.log(`The large message of ${bytes} bytes: Google signed it with ${largeKey}, and the signature does NOT pass the validators' check.`);
}
console.log('');

// The list of the good pairs, as the signing server reads it (src/pairs.js).
const list = `${JSON.stringify({
  about: `The wallet pairs of the signing server's kms key store: per pair its number, its two public keys in hex, and the full names of its two key versions in Google Cloud KMS. Written by ceremony/check.mjs from the key ceremony's run ${ring.stamp}. Public keys and names only, nothing secret.`,
  keyRing,
  pairs: good,
}, null, 2)}\n`;
if (good.length === 0) {
  console.log('No pair is good, so no list was written.');
} else {
  writeFileSync(join(run, 'wallet-pairs.json'), list, { mode: 0o600 });
  console.log(`The good pairs, ${good.length} of them, are listed in ${join(run, 'wallet-pairs.json')}`);
}

let written = false;
if (args.writeList) {
  if (ring.ring !== REAL_RING) {
    console.log(`The list was NOT written to the repo: this run's key ring is ${ring.ring}, and the repo's list is for the key ring ${REAL_RING} alone.`);
  } else if (good.length < args.pairs) {
    const missing = args.pairs - good.length;
    console.log(`The list was NOT written to the repo: ${good.length} ${good.length === 1 ? 'pair is' : 'pairs are'} good and ${args.pairs} are asked for, so ${missing} ${missing === 1 ? 'is' : 'are'} missing.`);
  } else {
    mkdirSync(dirname(LIST), { recursive: true });
    writeFileSync(LIST, list);
    written = true;
    console.log(`The list was written to ${LIST} (${good.length} pairs). Commit that file and push it.`);
  }
}
process.exit((args.writeList ? written : good.length === pairs.length) ? 0 : 1);
