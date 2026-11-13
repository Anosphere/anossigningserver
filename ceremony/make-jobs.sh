#!/usr/bin/env bash
# The key ceremony, step 1 of 4, in Cloud Shell (ceremony/README.md).
#
#   bash make-jobs.sh <project> [--ring <name>]
#
# Run it in the Google account that owns the project. The project is its
# first word and goes to every call: the script never acts on the project
# Cloud Shell happens to be set to. The location is europe. The key ring is
# wallet-pairs unless --ring names another one, which makes the run a dry
# run: the Mac then takes the pack with --dry-run only.
#
# It switches the Cloud KMS API on when it is not, makes the key ring when
# it is missing, and makes two import jobs at the software protection
# level, one for the ML-DSA-87 keys (a quantum-safe job with ML-KEM-1024)
# and one for the P-256 keys (an RSA job). It waits until both are ACTIVE
# and saves each job's public key. Nothing secret is made or sent here: an
# import job and its public key are all there is. The Mac wraps the key
# files for these two public keys in step 2.
#
# A run is known by its stamp: the month, the day and the time this script
# ran, in UTC. The jobs pack carries it in its name,
# ~/wallet-pairs-jobs-<stamp>.tgz, and is offered for download at the end.
# It holds four files:
#
#   ring.txt       the project, the location, the key ring, the stamp and
#                  the time the jobs were made
#   jobs.txt       per job: mldsa or p256, the job's name, its method, the
#                  file with its public key
#   mlkem.pub.b64  the quantum-safe job's publicKey.data, as gcloud prints it
#   rsa.pub.pem    the RSA job's public key, PEM text
#
# In the key ring wallet-pairs a key is called pair-001-p256 or
# pair-001-mldsa. In any other ring the key names end in the stamp
# (pair-001-p256-<stamp>), so a dry run can be repeated: a key's name can
# never be freed. make-pairs.mjs applies that rule when it writes the
# manifest.
#
# An import job lasts three days. Run this again for fresh jobs.
set -u

USAGE='bash make-jobs.sh <project> [--ring <name>]'
PROJECT="${1:-}"
case "$PROJECT" in
  ''|-*)
    echo "Give the project first:  $USAGE"
    exit 1
    ;;
esac
shift
LOCATION=europe
RING=wallet-pairs
while [ $# -gt 0 ]; do
  case "$1" in
    --ring)
      if [ $# -lt 2 ]; then
        echo "--ring needs a name after it:  $USAGE"
        exit 1
      fi
      RING="$2"
      shift 2
      ;;
    *)
      echo "Not understood: $1"
      echo "  $USAGE"
      exit 1
      ;;
  esac
done
case "$PROJECT$RING" in
  *[!A-Za-z0-9._-]*)
    echo "The project and the key ring may hold letters, digits, dots, dashes and underscores only."
    exit 1
    ;;
esac

MADE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="${MADE:5:2}${MADE:8:2}-${MADE:11:2}${MADE:14:2}${MADE:17:2}"
NAME="wallet-pairs-jobs-$STAMP"
DIR="$HOME/$NAME"
PACK="$HOME/$NAME.tgz"
JOB_MLDSA="bring-in-mlkem-$STAMP"
JOB_P256="bring-in-rsa-$STAMP"
METHOD_MLDSA=hpke-kem-ml-kem-1024-hkdf-sha256-aes-256-gcm
METHOD_P256=rsa-oaep-3072-sha256-aes-256

umask 077
TMP="$(mktemp -d)"
mkdir -p "$DIR"
: > "$DIR/jobs.txt"

say() { printf '%s\n' "$*"; }
why() { if [ -f "$1" ]; then tr '\n' ' ' < "$1" | cut -c1-400; fi; }
# Every call names the project, and none ever waits for an answer typed in.
g() { gcloud --quiet --project "$PROJECT" "$@"; }
k() { g kms "$@"; }

# Makes one import job, waits for ACTIVE and saves its public key. A job
# that is ready gets its line in jobs.txt.
make_job() {  # step, what it is for, mldsa or p256, the job, its method, the public key's field, the public key's file
  local step="$1" what="$2" half="$3" job="$4" method="$5" field="$6" file="$7"
  local err="$TMP/job-$3.err" state="" i
  if ! k import-jobs create "$job" --keyring "$RING" --location "$LOCATION" \
    --import-method "$method" --protection-level software >/dev/null 2>"$err"; then
    say "$step. The import job for the $what keys: FAILED: $(why "$err")"
    return 1
  fi
  for i in $(seq 1 90); do
    state="$(k import-jobs describe "$job" --keyring "$RING" --location "$LOCATION" --format='value(state)' 2>/dev/null)"
    if [ "$state" = ACTIVE ]; then break; fi
    sleep 4
  done
  say "$step. The import job for the $what keys ($job, method $method): ${state:-no answer}"
  if [ "$state" != ACTIVE ]; then return 1; fi

  if [ "$half" = mldsa ]; then
    # The raw ML-KEM key in base64, in one line. gcloud prints it in the URL-safe alphabet.
    k import-jobs describe "$job" --keyring "$RING" --location "$LOCATION" --format="value($field)" 2>"$err" \
      | tr -d ' \n\r' > "$DIR/$file"
    if [ ! -s "$DIR/$file" ]; then
      say "   its public key: NOT GIVEN: $(why "$err")"
      return 1
    fi
    say "   its public key ($field): $(tr '_-' '/+' < "$DIR/$file" | base64 -d 2>/dev/null | wc -c | tr -d ' ') bytes"
  else
    k import-jobs describe "$job" --keyring "$RING" --location "$LOCATION" --format="value($field)" > "$DIR/$file" 2>"$err"
    if ! grep -q 'BEGIN PUBLIC KEY' "$DIR/$file"; then
      say "   its public key: NOT GIVEN: $(why "$err")"
      return 1
    fi
    say "   its public key ($field): $(wc -c < "$DIR/$file" | tr -d ' ') characters of PEM text"
  fi
  printf '%s %s %s %s\n' "$half" "$job" "$method" "$file" >> "$DIR/jobs.txt"
}

say "The key ceremony, step 1 of 4, run $STAMP: project $PROJECT, location $LOCATION, key ring $RING"
say "gcloud: $(gcloud --version 2>/dev/null | head -n 1)"
if [ "$RING" != wallet-pairs ]; then
  say "This is a dry run: the key ring is not wallet-pairs."
fi

# 1. The Cloud KMS API, switched on when it is not.
if [ -n "$(g services list --enabled --filter='config.name=cloudkms.googleapis.com' --format='value(config.name)' 2>"$TMP/api.err")" ]; then
  say "1. The Cloud KMS API: already on"
elif g services enable cloudkms.googleapis.com >/dev/null 2>"$TMP/api.err"; then
  say "1. The Cloud KMS API: switched on"
else
  say "1. The Cloud KMS API: FAILED: $(why "$TMP/api.err")"
  say "Stopped. The project needs a billing account, and you need to be its owner."
  exit 1
fi

# 2. The key ring, made when it is missing. Right after the API is switched
#    on the first call may fail for a few seconds: up to six tries, five
#    seconds apart.
ring=""
try=1
while [ -z "$ring" ]; do
  if k keyrings describe "$RING" --location "$LOCATION" >/dev/null 2>"$TMP/ring.err"; then
    ring="already there"
  elif k keyrings create "$RING" --location "$LOCATION" >/dev/null 2>"$TMP/ring.err"; then
    ring="made"
  elif [ "$try" -ge 6 ]; then
    say "2. Key ring $RING in $LOCATION: FAILED: $(why "$TMP/ring.err")"
    say "Stopped."
    exit 1
  else
    try=$((try + 1))
    sleep 5
  fi
done
say "2. Key ring $RING in $LOCATION: $ring"

# 3. and 4. The two import jobs.
make_job 3 ML-DSA-87 mldsa "$JOB_MLDSA" "$METHOD_MLDSA" publicKey.data mlkem.pub.b64 || true
make_job 4 P-256 p256 "$JOB_P256" "$METHOD_P256" publicKey.pem rsa.pub.pem || true

ready="$(wc -l < "$DIR/jobs.txt" | tr -d ' ')"
say "5. Import jobs ACTIVE and ready for the Mac: $ready of 2"
if [ "$ready" != 2 ]; then
  say "Stopped. Nothing was packed. Run this line again for two fresh jobs."
  exit 1
fi

# 6. The jobs pack.
printf 'project %s\nlocation %s\nring %s\nstamp %s\nmade %s\n' "$PROJECT" "$LOCATION" "$RING" "$STAMP" "$MADE" > "$DIR/ring.txt"
tar -czf "$PACK" -C "$HOME" "$NAME"
say "6. Packed: $PACK ($(wc -c < "$PACK" | tr -d ' ') bytes)"
echo
echo "Now get that file onto the Mac, into its Downloads folder. A download window should open."
echo "If none does: the three dots at the top right of Cloud Shell, Download, and type $NAME.tgz"
echo "The import jobs last three days. Next, on the Mac with the network off: make-pairs.mjs (ceremony/README.md, step 2)."
if command -v cloudshell >/dev/null 2>&1; then
  cloudshell download "$PACK" || true
fi
