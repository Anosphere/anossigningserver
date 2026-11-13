#!/usr/bin/env node
// The key ceremony, step 2 of 4, on the Mac (ceremony/README.md).
//
//   node make-pairs.mjs --out <folder> [--out <folder>] [--jobs <pack>] [--pairs 100] [--from 1] [--work <folder>]
//   node make-pairs.mjs --dry-run [--jobs <pack>] [--pairs 100] [--from 1] [--work <folder>]
//   node make-pairs.mjs --rewrap --out <folder> [--jobs <pack>] [--work <folder>]
//
// Makes the wallet pairs, a P-256 key and an ML-DSA-87 key each, writes
// the private key files onto the encrypted drives and nowhere else, and
// wraps each key file for the import jobs Cloud Shell made in step 1, so
// that only Google Cloud KMS can open it. The Mac's own disk gets wrapped
// files and public keys alone, in the work folder. Prints names, sizes and
// public keys, never a byte of a private key.
//
//   --out      a folder on an encrypted drive, given once per drive
//   --jobs     the jobs pack of step 1; when left out, the newest
//              wallet-pairs-jobs-*.tgz in ~/Downloads
//   --pairs    how many pairs to make; 100 when left out
//   --from     the number of the first pair; 1 when left out
//   --work     the work folder, ~/Desktop/wallet-pairs-work when left out:
//              the one place on the Mac's own disk this script writes to.
//              Each run has a folder of its own there, named by its stamp.
//   --dry-run  throwaway keys for a key ring other than wallet-pairs: the
//              key files go into dry-run-keys/ in the run's work folder in
//              place of a drive, and the network may be on
//   --rewrap   makes no key and writes nothing onto a drive: wraps every
//              key file the first --out folder holds for the jobs of the
//              pack. For import jobs that ended before the keys were in,
//              and for bringing a key in again one day.
//
// It stops before anything is made:
//   - when the Mac has a network address that is neither internal nor
//     link-local. This holds for every run but a dry run.
//   - when the jobs pack is unusable, when its import jobs were made more
//     than 70 hours ago, or when its key ring is not the run's: a run with
//     --out takes the key ring wallet-pairs only, a dry run every key ring
//     but that one.
//   - when a key file it would write is already in a folder. A key file is
//     never overwritten.

import { execFileSync } from 'node:child_process';
import { ECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, networkInterfaces } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KEMS, sealForImportJob } from './hpke.mjs';
import { importJobRsaKey, wrapForRsaImportJob } from './rsa-aes-wrap.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const TAR = '/usr/bin/tar';

/** The key ring of the real wallet pairs. Every other key ring is a dry run's. */
const REAL_RING = 'wallet-pairs';

/** An import job ends 72 hours after it was made. A pack whose jobs are older than this is refused. */
const JOBS_MAX_HOURS = 70;

/** The KEM of the import job for the ML-DSA-87 keys, and the two import methods, as make-jobs.sh makes them. */
const KEM = 'ml-kem-1024';
const METHODS = { mldsa: 'hpke-kem-ml-kem-1024-hkdf-sha256-aes-256-gcm', p256: 'rsa-oaep-3072-sha256-aes-256' };

/**
 * The two halves of a pair. Per half: its name in a file name and in a
 * key's name in Google, its name in public.json and in the list of pairs,
 * the algorithm Google brings it in as, the size of its key file, and the
 * framing: the fixed bytes of the key file around the secret, each with
 * its place. A P-256 key file is the PKCS #8 file of 138 bytes: 36 bytes,
 * the 32-byte secret, 6 bytes, then the two halves of the public point. An
 * ML-DSA-87 key file is the PKCS #8 file of 54 bytes that holds the seed
 * alone: 22 bytes, then the 32-byte seed. These are the forms Google took
 * in the tries, and the only form it takes for an ML-DSA-87 key.
 */
const HALVES = [
  {
    half: 'p256',
    field: 'walletKey',
    algorithm: 'ec-sign-p256-sha256',
    fileBytes: 138,
    framing: [[0, '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420'], [68, 'a14403420004']],
  },
  {
    half: 'mldsa',
    field: 'walletPostQuantumKey',
    algorithm: 'pq-sign-ml-dsa-87',
    fileBytes: 54,
    framing: [[0, '3034020100300b060960864801650304031304228020']],
  },
];

/** What is signed to see that a key file signs for its own public key. */
const SELF_TEST = Buffer.from('the key ceremony of the wallet pairs: a key file signs for its public key', 'utf8');

const SAFE = /^[A-Za-z0-9._-]+$/;
const STAMP = /^\d{4}-\d{6}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const KEY_FILE = /^pair-(\d{3})-(p256|mldsa)\.der$/;

const USAGE = `  node make-pairs.mjs --out <folder> [--out <folder>] [--jobs <pack>] [--pairs 100] [--from 1] [--work <folder>]
  node make-pairs.mjs --dry-run [--jobs <pack>] [--pairs 100] [--from 1] [--work <folder>]
  node make-pairs.mjs --rewrap --out <folder> [--jobs <pack>] [--work <folder>]`;

/** A pair's number in three digits, as every name carries it. */
const three = (number) => String(number).padStart(3, '0');

/** The name of a key file on a drive. */
const keyFile = (number, half) => `pair-${three(number)}-${half}.der`;

const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');

/** Ends the run with the reason. Nothing was made when this is called before the keys. */
function stop(reason) {
  console.log(`Stopped: ${reason}`);
  process.exit(1);
}

/** Ends the run over a line that is not understood. */
function usage(reason) {
  console.log(`${reason}\n\n${USAGE}`);
  process.exit(1);
}

/** The words after `node make-pairs.mjs`, checked against the three forms above. */
function readArguments(words) {
  const args = { out: [], jobs: null, pairs: null, from: null, work: null, dryRun: false, rewrap: false };
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const value = () => {
      if (i + 1 >= words.length) usage(`${word} needs a value after it.`);
      return words[++i];
    };
    const count = () => {
      const text = value();
      if (!/^[1-9][0-9]{0,2}$/.test(text)) usage(`${word} takes a number from 1 to 999, not ${text}.`);
      return Number(text);
    };
    if (word === '--out') args.out.push(resolve(value()));
    else if (word === '--jobs') args.jobs = resolve(value());
    else if (word === '--work') args.work = resolve(value());
    else if (word === '--pairs') args.pairs = count();
    else if (word === '--from') args.from = count();
    else if (word === '--dry-run') args.dryRun = true;
    else if (word === '--rewrap') args.rewrap = true;
    else usage(`Not understood: ${word}`);
  }
  if (args.dryRun && args.out.length > 0) usage('--dry-run does not go together with --out: a dry run writes no drive.');
  if (args.dryRun && args.rewrap) usage('--rewrap does not go together with --dry-run.');
  if (!args.dryRun && args.out.length === 0) usage('Give --out once per drive, or --dry-run.');
  if (new Set(args.out).size !== args.out.length) usage('The same folder is named twice with --out.');
  if (args.rewrap && (args.pairs !== null || args.from !== null)) usage('--rewrap makes no key, so --pairs and --from do not go with it.');
  args.pairs ??= 100;
  args.from ??= 1;
  if (args.from + args.pairs - 1 > 999) usage('A pair\'s number has three digits: --from and --pairs together go past 999.');
  args.work ??= join(homedir(), 'Desktop', 'wallet-pairs-work');
  return args;
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
  if (Number.isNaN(Date.parse(ring.made))) throw new Error('ring.txt has no usable made');
  return ring;
}

/**
 * The raw ML-KEM public key out of what the import job gave. Expected are
 * the raw bytes themselves, which is what gcloud prints as publicKey.data;
 * the DER and PEM forms are read too. Null for anything else.
 */
function rawMlKemKey(given) {
  const kem = KEMS[KEM];
  if (given.length === kem.publicKeyBytes) return given;
  for (const options of [{ key: given, format: 'der', type: 'spki' }, { key: given.toString('latin1'), format: 'pem' }]) {
    try {
      const key = createPublicKey(options);
      if (key.asymmetricKeyType !== KEM) continue;
      const spki = key.export({ type: 'spki', format: 'der' });
      return spki.subarray(spki.length - kem.publicKeyBytes);
    } catch {
      // not this form
    }
  }
  return null;
}

/**
 * The jobs pack of step 1, read as data: the pack is listed and each of
 * its four files is read out of it into memory, so nothing is unpacked
 * onto the disk. Returns the run's ring.txt and, per half, the import
 * job's name and its public key. Throws with what is wrong with the pack.
 */
function readJobsPack(pack) {
  let members;
  try {
    members = execFileSync(TAR, ['-tzf', pack], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
      .split('\n').filter((member) => member !== '').map((member) => member.replace(/^\.\//, ''));
  } catch {
    throw new Error('tar cannot read it');
  }
  const top = (members[0] ?? '').split('/')[0];
  if (!/^wallet-pairs-jobs-\d{4}-\d{6}$/.test(top)) throw new Error('it holds no folder wallet-pairs-jobs-<stamp>');
  const read = (name) => {
    if (!members.includes(`${top}/${name}`)) throw new Error(`it holds no ${name}`);
    return execFileSync(TAR, ['-xzOf', pack, `${top}/${name}`], { stdio: ['ignore', 'pipe', 'pipe'] });
  };

  const ring = readRing(read('ring.txt').toString('utf8'));
  if (top !== `wallet-pairs-jobs-${ring.stamp}`) throw new Error('its folder and its ring.txt name two different stamps');

  const jobs = {};
  for (const line of read('jobs.txt').toString('utf8').split('\n')) {
    if (line.trim() === '') continue;
    const [half, job, method, file, ...more] = line.trim().split(/\s+/);
    if (!Object.hasOwn(METHODS, half) || Object.hasOwn(jobs, half) || more.length > 0
      || ![job, method, file].every((word) => word !== undefined && SAFE.test(word))) {
      throw new Error('a line of jobs.txt is not understood');
    }
    if (method !== METHODS[half]) throw new Error(`its import job for the ${half} keys has the method ${method}, not ${METHODS[half]}`);
    jobs[half] = { job, file };
  }
  for (const half of Object.keys(METHODS)) {
    if (!Object.hasOwn(jobs, half)) throw new Error(`it names no import job for the ${half} keys`);
  }

  const mlKemText = read(jobs.mldsa.file).toString('latin1');
  const rsaText = read(jobs.p256.file).toString('utf8');
  const mlKemKey = rawMlKemKey(Buffer.from(mlKemText.trim(), 'base64'));
  if (mlKemKey === null) throw new Error(`the public key of ${jobs.mldsa.job} is not an ML-KEM-1024 key`);
  let rsaKey;
  try {
    rsaKey = importJobRsaKey(rsaText);
  } catch (error) {
    throw new Error(`the public key of ${jobs.p256.job} is not usable: ${error.message}`);
  }
  return { ring, jobs: { mldsa: { job: jobs.mldsa.job, publicKey: mlKemKey }, p256: { job: jobs.p256.job, publicKey: rsaKey } } };
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

/** A fresh key of one half as its key file, checked as every key file is before it goes on. */
function makeKeyFile(half) {
  const { privateKey } = half === 'p256'
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : generateKeyPairSync('ml-dsa-87');
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  publicKeyOf(half, der);
  return der;
}

/**
 * Every pair a folder holds, in the order of the numbers: per pair its
 * number, its two key files as they are on the drive, and its two public
 * keys in hex. Throws when a pair has one key file only, or when a key
 * file is not what publicKeyOf asks for.
 */
function readFolder(folder) {
  const found = new Map();
  for (const name of readdirSync(folder)) {
    const match = KEY_FILE.exec(name);
    if (match === null) continue;
    const number = Number(match[1]);
    found.set(number, (found.get(number) ?? new Set()).add(match[2]));
  }
  const pairs = [];
  for (const number of [...found.keys()].sort((a, b) => a - b)) {
    const files = {};
    const publicKeys = {};
    for (const { half, field } of HALVES) {
      const path = join(folder, keyFile(number, half));
      if (!found.get(number).has(half)) throw new Error(`${path} is missing: pair ${three(number)} has one key file only`);
      files[half] = readFileSync(path);
      try {
        publicKeys[field] = publicKeyOf(half, files[half]).toString('hex');
      } catch (error) {
        throw new Error(`${path} ${error.message}`);
      }
    }
    pairs.push({ number, files, publicKeys });
  }
  return pairs;
}

/** Wipes the key files a readFolder held in memory. */
function forget(pairs) {
  for (const { files } of pairs) for (const der of Object.values(files)) der.fill(0);
}

/** public.json: each pair's number and its two public keys. */
function publicJson(pairs) {
  return `${JSON.stringify({
    about: 'The public keys of the wallet pairs: per pair its number, its P-256 key as the 33-byte compressed point and its ML-DSA-87 key as its 2592 bytes, both in hex. Written by ceremony/make-pairs.mjs. Nothing here is secret.',
    pairs: pairs.map(({ number, publicKeys }) => ({ number, ...publicKeys })),
  }, null, 2)}\n`;
}

/**
 * Writes what a drive's folder holds beside its key files, anew, over
 * every pair the folder holds: public.json, SHA256SUMS over the key files
 * and public.json (in the form shasum reads), and code/, a copy of
 * ceremony/ and of src/crypto/ in their places, so the scripts run from
 * the drive.
 */
function writeBesideKeys(folder, pairs) {
  writeFileSync(join(folder, 'public.json'), publicJson(pairs));
  const names = [...pairs.flatMap(({ number }) => HALVES.map(({ half }) => keyFile(number, half))), 'public.json'];
  writeFileSync(join(folder, 'SHA256SUMS'), names.map((name) => `${sha256Hex(readFileSync(join(folder, name)))}  ${name}\n`).join(''));

  for (const [from, to] of [[here, join(folder, 'code', 'ceremony')], [join(here, '..', 'src', 'crypto'), join(folder, 'code', 'src', 'crypto')]]) {
    mkdirSync(to, { recursive: true });
    // Run from a drive's own copy, the copy is already where it belongs.
    if (realpathSync(from) === realpathSync(to)) continue;
    for (const entry of readdirSync(from, { withFileTypes: true })) {
      if (entry.isFile() && !entry.name.startsWith('.')) copyFileSync(join(from, entry.name), join(to, entry.name));
    }
  }
}

/** Every file under a folder, by its path inside it, with its SHA-256. Names that start with a dot are the Mac's own and are left out. */
function filesOf(folder, inside = '') {
  const found = new Map();
  for (const entry of readdirSync(join(folder, inside), { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const path = inside === '' ? entry.name : `${inside}/${entry.name}`;
    if (entry.isDirectory()) {
      for (const [name, sum] of filesOf(folder, path)) found.set(name, sum);
    } else if (entry.isFile()) {
      found.set(path, sha256Hex(readFileSync(join(folder, path))));
    }
  }
  return found;
}

/**
 * Wraps every key file of `pairs` for its import job and packs the run's
 * folder for Cloud Shell: the wrapped files, manifest.txt (per key: the
 * pair's number, the key's name in Google, the import job, the algorithm,
 * the wrapped file), ring.txt, public.json, the two messages every key
 * signs in step 3, and a copy of bring-in.sh. The folder and the pack are
 * written anew. In the key ring wallet-pairs a key is called
 * pair-NNN-p256 or pair-NNN-mldsa; in any other ring the name ends in the
 * run's stamp, because a key's name can never be freed and a dry run has
 * to be repeatable. Returns the pack's path and the number of wrapped
 * files.
 */
function wrapAndPack(pairs, ring, jobs, work) {
  const run = join(work, ring.stamp);
  const name = `wallet-pairs-wrapped-${ring.stamp}`;
  const folder = join(run, name);
  rmSync(folder, { recursive: true, force: true });
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const write = (file, data) => writeFileSync(join(folder, file), data, { mode: 0o600 });

  const manifest = [];
  for (const { number, files } of pairs) {
    for (const { half, algorithm } of HALVES) {
      const der = files[half];
      const wrapped = half === 'mldsa'
        ? sealForImportJob(KEM, jobs.mldsa.publicKey, der)
        : wrapForRsaImportJob(jobs.p256.publicKey, der);
      const expected = half === 'mldsa'
        ? KEMS[KEM].encBytes + der.length + 16
        : 384 + Math.ceil(der.length / 8) * 8 + 8;
      if (wrapped.length !== expected) throw new Error(`${keyFile(number, half)}: wrapped to ${wrapped.length} bytes, expected ${expected}`);
      const base = `pair-${three(number)}-${half}`;
      write(`${base}.bin`, wrapped);
      manifest.push(`${number} ${ring.ring === REAL_RING ? base : `${base}-${ring.stamp}`} ${jobs[half].job} ${algorithm} ${base}.bin`);
    }
  }
  write('manifest.txt', `${manifest.join('\n')}\n`);
  write('ring.txt', ['project', 'location', 'ring', 'stamp', 'made'].map((field) => `${field} ${ring[field]}\n`).join(''));
  write('public.json', publicJson(pairs));
  write('msg-small.txt', `The key ceremony of the wallet pairs, run ${ring.stamp}.\n`);
  write('msg-large.bin', randomBytes(45_000));
  copyFileSync(join(here, 'bring-in.sh'), join(folder, 'bring-in.sh'));

  const pack = join(run, `${name}.tgz`);
  rmSync(pack, { force: true });
  execFileSync(TAR, ['--no-xattrs', '-czf', pack, '-C', run, name], { env: { ...process.env, COPYFILE_DISABLE: '1' } });
  chmodSync(pack, 0o600);
  return { pack, wrapped: manifest.length };
}

// --- the run -------------------------------------------------------------------------

const args = readArguments(process.argv.slice(2));
for (const needed of ['bring-in.sh', join('..', 'src', 'crypto', 'signatures.js')]) {
  if (!existsSync(join(here, needed))) stop(`${join(here, needed)} is missing: this script runs from the repo's ceremony folder, or from a drive's copy of it.`);
}

console.log(args.rewrap
  ? 'The key ceremony, step 2 of 4: the key files of a drive are wrapped again. No key is made.'
  : args.dryRun
    ? 'The key ceremony, step 2 of 4, as a dry run: throwaway keys.'
    : 'The key ceremony, step 2 of 4: the wallet pairs are made and wrapped.');

// 1. The network.
if (args.dryRun) {
  console.log('The network: not looked at in a dry run.');
} else {
  const addresses = networkAddresses();
  if (addresses.length > 0) {
    stop(`the network is on (${addresses.join(', ')}). Switch Wi-Fi off and pull the cable, then run this line again.`);
  }
  console.log('The network: off.');
}

// 2. The jobs pack.
const pack = args.jobs ?? newestDownload('wallet-pairs-jobs-');
if (pack === null || !existsSync(pack)) {
  stop(`there is no jobs pack${pack ? ` at ${pack}` : ' in ~/Downloads'}. Download wallet-pairs-jobs-<stamp>.tgz from Cloud Shell first (step 1), or name it with --jobs.`);
}
let ring;
let jobs;
try {
  ({ ring, jobs } = readJobsPack(pack));
} catch (error) {
  stop(`the jobs pack is unusable: ${error.message}. The pack: ${pack}. Run make-jobs.sh in Cloud Shell again (step 1) and take the new pack.`);
}
const hours = (Date.now() - Date.parse(ring.made)) / 3_600_000;
console.log(`The jobs pack: ${pack}`);
console.log(`  run ${ring.stamp}: project ${ring.project}, location ${ring.location}, key ring ${ring.ring}; its import jobs were made ${ring.made}, ${Math.max(0, Math.floor(hours))} hours ago`);
console.log(`  ${jobs.mldsa.job}, for the ML-DSA-87 keys: an ML-KEM-1024 public key of ${jobs.mldsa.publicKey.length} bytes`);
console.log(`  ${jobs.p256.job}, for the P-256 keys: an RSA public key of ${jobs.p256.publicKey.asymmetricKeyDetails.modulusLength} bits`);
if (hours > JOBS_MAX_HOURS) {
  stop(`the jobs pack is too old: its import jobs were made ${Math.floor(hours)} hours ago, and an import job ends after 72. Run make-jobs.sh in Cloud Shell again (step 1) and take the new pack.`);
}
if (args.dryRun && ring.ring === REAL_RING) {
  stop(`the jobs pack is for the key ring ${REAL_RING}, and a dry run takes every key ring but that one. For a dry run, step 1 is: bash make-jobs.sh <project> --ring kms-try`);
}
if (!args.dryRun && ring.ring !== REAL_RING) {
  stop(`the jobs pack is for another key ring, ${ring.ring}: a run with --out takes the key ring ${REAL_RING} only. The newest pack in ~/Downloads is not this run's. Run make-jobs.sh in Cloud Shell again (step 1), then this line again.`);
}

// 3. The folders, and the key files this run would write.
const run = join(args.work, ring.stamp);
const folders = args.dryRun ? [join(run, 'dry-run-keys')] : args.out;
const numbers = args.rewrap ? [] : Array.from({ length: args.pairs }, (_, i) => args.from + i);
for (const folder of folders) {
  if (existsSync(folder)) {
    if (!statSync(folder).isDirectory()) stop(`${folder} is not a folder.`);
    const there = numbers.flatMap((number) => HALVES.map(({ half }) => join(folder, keyFile(number, half)))).filter((path) => existsSync(path));
    if (there.length > 0) {
      stop(`a key file is already there: ${there[0]}${there.length > 1 ? ` (and ${there.length - 1} more of this run's)` : ''}. A key file is never overwritten. An earlier run wrote that pair: stop and look.`);
    }
  } else if (args.rewrap) {
    stop(`${folder} is not there. Is the drive plugged in and unlocked?`);
  } else if (!args.dryRun && !existsSync(dirname(folder))) {
    stop(`${dirname(folder)} is not there, so ${folder} cannot be made. Is the drive plugged in and unlocked?`);
  }
}

// 4. The keys: made, checked, and written to every folder before the next pair.
if (!args.rewrap) {
  for (const folder of folders) {
    if (existsSync(folder)) continue;
    try {
      mkdirSync(folder, { recursive: args.dryRun, mode: 0o700 });
    } catch (error) {
      stop(`${folder} could not be made (${error.code ?? error.message}). No key was made. When macOS asks whether Terminal may reach files on a removable volume, the answer is yes.`);
    }
  }
  console.log(`Making ${numbers.length === 1 ? `pair ${three(numbers[0])}` : `pairs ${three(numbers[0])} to ${three(numbers.at(-1))}`}:`);
  for (const number of numbers) {
    const sizes = [];
    for (const { half } of HALVES) {
      const der = makeKeyFile(half);
      for (const folder of folders) {
        const path = join(folder, keyFile(number, half));
        try {
          writeFileSync(path, der, { mode: 0o600, flag: 'wx', flush: true });
        } catch (error) {
          der.fill(0);
          stop(`${path} could not be written (${error.code ?? error.message}). The pairs before ${three(number)} are whole in every folder; pair ${three(number)} may be in one folder and not in another. Stop and look before any other run.`);
        }
      }
      sizes.push(`${keyFile(number, half)} ${der.length} bytes`);
      der.fill(0);
    }
    console.log(`  pair ${three(number)}: ${sizes.join(', ')}`);
  }
}

// 5. Every folder read back: its pairs, and for a run that made keys what lies beside them.
let first = null;
for (const folder of folders) {
  let pairs;
  try {
    pairs = readFolder(folder);
  } catch (error) {
    stop(`${error.message}. Stop and look before any other run.`);
  }
  if (pairs.length === 0) stop(`${folder} holds no key file.`);
  if (!args.rewrap) writeBesideKeys(folder, pairs);
  console.log(`${folder}: ${pairs.length * 2} key files, ${pairs.length} ${pairs.length === 1 ? 'pair' : 'pairs'}${args.rewrap ? '' : ', with public.json, SHA256SUMS and code/'}`);
  if (first === null) first = pairs;
  else forget(pairs);
  if (args.rewrap) break;
}

// 6. With more than one folder: do they hold the same files?
if (!args.rewrap && folders.length > 1) {
  const mine = filesOf(folders[0]);
  for (const other of folders.slice(1)) {
    const theirs = filesOf(other);
    const differ = [
      ...[...mine.keys()].filter((name) => !theirs.has(name)).map((name) => `${name} is in ${folders[0]} only`),
      ...[...theirs.keys()].filter((name) => !mine.has(name)).map((name) => `${name} is in ${other} only`),
      ...[...mine.keys()].filter((name) => theirs.has(name) && theirs.get(name) !== mine.get(name)).map((name) => `${name} is not the same in both`),
    ];
    if (differ.length > 0) {
      forget(first);
      for (const line of differ.slice(0, 20)) console.log(`  ${line}`);
      stop(`${folders[0]} and ${other} do NOT hold the same files: ${differ.length} ${differ.length === 1 ? 'file differs' : 'files differ'}. This run's key files are in the folders, and nothing was wrapped. Stop and look. Once the folders are right, --rewrap --out "${folders[0]}" makes the pack and no key.`);
    }
  }
  console.log(`${folders.length === 2 ? 'Both' : `All ${folders.length}`} folders hold the same files: ${mine.size} files each, the same bytes.`);
}

// 7. Wrapped for Google, from the first folder, and packed.
const packed = wrapAndPack(first, ring, jobs, args.work);
forget(first);
console.log(`Wrapped for Google, from ${folders[0]}: ${packed.wrapped} key files of ${first.length} ${first.length === 1 ? 'pair' : 'pairs'}, for the key ring ${ring.ring}.`);
console.log(`The pack: ${packed.pack} (${statSync(packed.pack).size} bytes)`);
console.log(`Upload that file to Cloud Shell. Its run there must end with "Brought in and ENABLED: ${packed.wrapped} of ${packed.wrapped}". The line to paste into Cloud Shell:`);
console.log(`tar xzf wallet-pairs-wrapped-${ring.stamp}.tgz && bash wallet-pairs-wrapped-${ring.stamp}/bring-in.sh`);
