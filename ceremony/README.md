# The key ceremony

The signing server's wallet pairs are made here and brought into Google
Cloud KMS. A wallet pair is a P-256 key and an ML-DSA-87 key. There are
100 pairs, which is 200 keys. Every account names one pair for life, so a
pair that is lost strands its accounts. That is why the keys are made
outside Google and kept on two encrypted drives: a key that Google loses
or destroys can be brought in again from a drive.

The rules of the ceremony:

- The keys are made on the Mac with the network off, while the drives are
  unlocked. The private key files go straight onto the drives and nowhere
  else.
- The Mac's own disk gets wrapped files and public keys alone, in one
  folder, `~/Desktop/wallet-pairs-work`.
- A key leaves the Mac only wrapped for an import job of Google Cloud KMS.
  Only Google can open it.
- No script prints a byte of a private key. They print names, sizes and
  public keys.
- In the key ring `wallet-pairs` nothing is ever destroyed.

On the Mac the scripts need Node 24 and the `tar` that macOS brings. In
Cloud Shell they need gcloud and what Cloud Shell brings. Nothing here is
installed with npm.

The lines below are written from the repo's root. The operator's own
how-to, with full paths and what must be seen at each point, is
`test_net_phase_3_production/signing-server-go-live.md` beside the repos.

## The four steps

A run is known by its stamp: the month, the day and the time step 1 ran,
in UTC, as in `1113-142233`. The three packs carry it in their names, so
the pack of one run can never be taken for another's.

**Step 1, Cloud Shell: the key ring and two import jobs.**

```bash
curl -fsSLO https://raw.githubusercontent.com/Anosphere/anossigningserver/main/ceremony/make-jobs.sh && bash make-jobs.sh signerkeys
```

`make-jobs.sh <project> [--ring <name>]`. The project is its first word
and goes to every call. It switches the Cloud KMS API on when it is not,
makes the key ring `wallet-pairs` in the location `europe` when it is
missing, and makes two import jobs: `bring-in-mlkem-<stamp>` for the
ML-DSA-87 keys (a quantum-safe job with ML-KEM-1024) and
`bring-in-rsa-<stamp>` for the P-256 keys. You must see the key ring and
both jobs `ACTIVE`. The jobs pack, `wallet-pairs-jobs-<stamp>.tgz`, is
offered for download: let it go to the Mac's Downloads folder. It holds
the two jobs' names and public keys, nothing secret.

An import job lasts three days.

**Step 2, the Mac, with the network off: the keys are made and wrapped.**
Wi-Fi off, no cable. Then plug in and unlock both drives.

```bash
node ceremony/make-pairs.mjs --out "/Volumes/<drive one>/wallet-pairs" --out "/Volumes/<drive two>/wallet-pairs"
```

It takes the newest jobs pack in `~/Downloads`. For each pair it makes
the two keys and writes them to both folders as `pair-001-p256.der` (138
bytes) and `pair-001-mldsa.der` (54 bytes), the pair's number in three
digits. You must see 200 key files in each folder and the line `Both
folders hold the same files`. Then it wraps every key file of the first
folder for its import job and packs the wrapped files. Its last lines
name the pack, `wallet-pairs-wrapped-<stamp>.tgz` in the run's folder
under `~/Desktop/wallet-pairs-work`, and give the line for step 3.

It stops before anything is made:

- when the network is on;
- when the jobs pack is unusable, when its jobs were made more than 70
  hours ago, or when its key ring is not `wallet-pairs`;
- when a key file it would write is already in a folder. A key file is
  never overwritten.

Then check each drive (below), eject both, lock them, unplug them. Only
then switch the network back on.

**Step 3, Cloud Shell: the keys are brought in.** Upload the pack step 2
named. Then paste the line step 2 printed:

```bash
tar xzf wallet-pairs-wrapped-<stamp>.tgz && bash wallet-pairs-wrapped-<stamp>/bring-in.sh
```

`bring-in.sh` travels in the pack and takes no word: the project, the
location and the key ring come from the pack. For each key it looks at
what Google holds under the key's name:

- no such key: the key is made as an import-only key and the wrapped file
  is brought in;
- the key with an `ENABLED` version: `already`, nothing is brought in;
- the key with no `ENABLED` version: the wrapped file is brought in as
  the key's next version.

Then every key that is in gives its public key and signs a short
message, and the first ML-DSA-87 key signs a message of 45,000 bytes,
the largest payload a validator would take. One line per key. You must
see `Brought in and ENABLED: 200 of 200`. The out pack,
`wallet-pairs-out-<stamp>.tgz`, is offered for download: let it go to
the Downloads folder.

The line can be pasted again at any time. Keys that are in read
`already`, the others are brought in. So it picks up where it stopped:
after a key that did not come in, and after Google ended the Cloud Shell
session in the middle of the run. With 200 keys the run takes many
minutes, one key after the other.

**Step 4, the Mac: the check, and the list of pairs.** The network may be
on. The drives stay where they are.

```bash
node ceremony/check.mjs --write-list
```

It takes the newest out pack in `~/Downloads` and the run with the same
stamp in the work folder. A pair is good when the two public keys Google
holds are the ones this Mac made and both of Google's signatures pass
`verifySignature` of `src/crypto/signatures.js`, the validators' own
check. One line per pair, `good` or `NOT GOOD` with what failed. You must
see `100 of 100 pairs good`.

One more line is about the large message. When it says Google refused
it, only a very large fund proposal is affected, and the limit has to be
written into this README and the repo's.

With `--write-list` it writes `network/wallet-pairs.json` in the repo
when the key ring is `wallet-pairs` and at least 100 pairs are good
(`--pairs` asks for another number). That file is the list the signing
server reads its pairs from: each pair's number, its two public keys and
the full names of its two key versions in Google. A pair that is not
good is left out. Commit the file and push it. It holds nothing secret.

## The names

| what | name |
| --- | --- |
| the key ring | `wallet-pairs`, in the location `europe` of the project `signerkeys` |
| a key in Google | `pair-001-p256`, `pair-001-mldsa`, to `pair-100-p256`, `pair-100-mldsa` |
| a key file on a drive | `pair-001-p256.der`, `pair-001-mldsa.der` |
| a wrapped file in a pack | `pair-001-p256.bin`, `pair-001-mldsa.bin` |
| the import jobs | `bring-in-mlkem-<stamp>`, `bring-in-rsa-<stamp>` |
| the packs | `wallet-pairs-jobs-<stamp>.tgz`, `wallet-pairs-wrapped-<stamp>.tgz`, `wallet-pairs-out-<stamp>.tgz` |
| a run's folder on the Mac | `~/Desktop/wallet-pairs-work/<stamp>/` |

A key's name in Google can never be freed, and a key ring can never be
deleted.

## The two drives, and what a drive holds

Two drives with the same files, written in the same sitting and kept in
two different places. The folder on a drive holds:

- the 200 private key files as they are, with no second password. The
  drive's own lock is the lock. A P-256 key file is the PKCS #8 file of
  138 bytes. An ML-DSA-87 key file is the PKCS #8 file of 54 bytes that
  holds the seed alone, the only form Google takes;
- `public.json`: each pair's number and its two public keys;
- `SHA256SUMS`: the checksums of the key files and of `public.json`, in
  the form `shasum -a 256 -c SHA256SUMS` reads;
- `code/`: a copy of this folder and of `src/crypto/` in their places,
  so the scripts run from the drive: `code/ceremony/README.md` is this
  note.

`make-pairs.mjs` writes `public.json`, `SHA256SUMS` and `code/` anew,
over every pair the folder holds, in every run that makes a key.

Never copy a drive's key files onto a computer's own disk.

## The drive check

With the network off, as in step 2, at any time:

```bash
node ceremony/check-drive.mjs "/Volumes/<drive>/wallet-pairs"
```

For every pair in the folder: both key files have their size and their
framing, each gives the public key `public.json` names and signs for it,
and the checksums hold. One line per pair. You must see `100 of 100
pairs good`.

Run from the repo once `network/wallet-pairs.json` is there, every pair
of the list must also be in the folder with the same public keys. A pair
of the folder that the list does not hold reads `good, not in the list`
and is no failure: it was left out because it was not good in Google.

## When something goes wrong

Every line that touches a drive is run with the network off and the
drives unlocked, as step 2.

**A key did not come in, or Cloud Shell closed while step 3 ran.** Fewer
than 200 of 200, or no last line at all. Paste the line of step 3 again.
A key's line gives Google's reason.

**A pair is not good in step 4.** That pair is left out, so fewer than
100 are good and the repo's list is not written. Make one more pair
under the next number, with the same `--out` folders:

```bash
node ceremony/make-pairs.mjs --from 101 --pairs 1 --out "/Volumes/<drive one>/wallet-pairs" --out "/Volumes/<drive two>/wallet-pairs"
```

Then steps 3 and 4 again. The pack then holds every pair of the drive,
the new and the old alike, so step 3 counts 202 keys and step 4 reads
`100 of 101 pairs good` and writes the list. The pair that was not good
stays on the drives and in Google and is never used. Before the launch
this is harmless, because no account names a pair yet.

**The import jobs ended.** Three days passed before step 3 was good, and
a key's line in step 3 says the import job is expired. Step 1 again for
fresh jobs. Then, with the network off and the first drive unlocked:

```bash
node ceremony/make-pairs.mjs --rewrap --out "/Volumes/<drive one>/wallet-pairs"
```

`--rewrap` makes no key and writes nothing onto a drive. It wraps every
key file the folder holds for the new jobs and makes a new pack, under
the new stamp. Then steps 3 and 4.

**The two folders do not hold the same files.** `make-pairs.mjs` names
the files that differ, wraps nothing and stops. The key files it made
are in the folders. Stop and look. Once the folders are right,
`--rewrap` with the first folder makes the pack.

**`make-pairs.mjs` stops because a key file is already there.** An
earlier run wrote that pair to this drive. Stop and look. The next free
number goes after `--from`.

## Bringing a key into Google again

For the day a key version in Google is destroyed or lost. This was never
tried. Google's pages say a destroyed imported key can be brought in
again with the same key file; nobody here has done it.

It is the path of import jobs that ended:

1. Step 1, for fresh import jobs.
2. With the network off and a drive unlocked, `--rewrap` with that
   drive's folder.
3. Step 3. Every key that is in reads `already`. The key without an
   `ENABLED` version is brought in as its next version, so its version
   number changes, for instance from 1 to 2.
4. Step 4 with `--write-list`. The list then names the new version.
   Commit it and push it, and update the two machines, one after the
   other: a signing server signs with the versions its list names.

## The dry run

A whole ceremony with throwaway keys, in another key ring. The network
may be on, and no drive is needed. The four steps are the same, with
these lines.

Step 1, in Cloud Shell, the line of step 1 with a key ring named:

```bash
bash make-jobs.sh signerkeys --ring kms-try
```

Step 2, on the Mac, for two pairs:

```bash
node ceremony/make-pairs.mjs --dry-run --pairs 2
```

Step 3 is the line step 2 prints. Step 4, on the Mac:

```bash
node ceremony/check.mjs
```

The key files go into `dry-run-keys/` in the run's work folder in place
of a drive. A dry run takes every key ring but `wallet-pairs`, and a run
with `--out` takes `wallet-pairs` alone, so a dry run's pack can never
be used for the real keys. In a dry run's key ring the key names end in
the stamp (`pair-001-p256-<stamp>`), so it can be repeated. The repo's
list is never written from a dry run. `check-drive.mjs` works on
`dry-run-keys/` too, with the network off.

`bash kms-try/clean-up.sh signerkeys` beside the repos schedules the
throwaway key versions in `kms-try` for destruction. It is for that key
ring alone.

## The files

```
make-jobs.sh       step 1, Cloud Shell: the key ring, the two import jobs, the jobs pack
make-pairs.mjs     step 2, the Mac: makes the pairs, writes the drives, wraps, packs
bring-in.sh        step 3, Cloud Shell: brings the wrapped files in, the out pack
check.mjs          step 4, the Mac: the validators' check, the list of pairs
check-drive.mjs    at any time, the Mac: checks a drive's folder
hpke.mjs           the wrap for the ML-DSA-87 keys: HPKE Seal with ML-KEM-1024
rsa-aes-wrap.mjs   the wrap for the P-256 keys: RSA-OAEP around an AES key wrap
```

The two wrap modules are the ones of the three tries against Google
Cloud KMS on 2026-11-10, unchanged. They were proven there against
published test vectors and against KMS itself.

What a pack holds:

- the jobs pack: `ring.txt` (the project, the location, the key ring,
  the stamp, the time the jobs were made), `jobs.txt`, `mlkem.pub.b64`,
  `rsa.pub.pem`;
- the wrapped pack: the wrapped files, `manifest.txt` (per key: the
  pair's number, the key's name in Google, the import job, the
  algorithm, the wrapped file), `ring.txt`, `public.json`,
  `msg-small.txt`, `msg-large.bin`, `bring-in.sh`;
- the out pack: `results.txt` (the lines of step 3), `ring.txt`,
  `versions.txt` (each key's `ENABLED` version), each key's public key
  and signature, and the large message's signature or Google's answer.
