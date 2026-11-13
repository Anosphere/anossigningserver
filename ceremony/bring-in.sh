#!/usr/bin/env bash
# The key ceremony, step 3 of 4, in Cloud Shell (ceremony/README.md).
#
#   tar xzf wallet-pairs-wrapped-<stamp>.tgz && bash wallet-pairs-wrapped-<stamp>/bring-in.sh
#
# Run it in the Google account that owns the project. It takes no word:
# everything it needs is in the pack the Mac made in step 2 and this script
# travels in. The project, the location and the key ring come from the
# pack's ring.txt and go to every call: the script never acts on the
# project Cloud Shell happens to be set to.
#
# For each line of the manifest (the pair's number, the key's name in
# Google, the import job, the algorithm, the wrapped file), by what Google
# holds under the key's name:
#
#   - no such key: the key is made as an import-only key, and the wrapped
#     file is brought in through its import job;
#   - the key with a version that is ENABLED: `already`. Nothing is
#     brought in;
#   - the key with no version that is ENABLED (none at all, a failed one, a
#     destroyed one): the wrapped file is brought in as the key's next
#     version.
#
# It waits for a new version's last state. Then, for every key with an
# ENABLED version, it fetches the public key Google holds and has Google
# sign the short message. The first ML-DSA-87 key also signs the large
# message. No key reaches this machine unwrapped: only the wrapped files
# do, and only Google Cloud KMS can open them.
#
# So the line can be pasted again at any time, and it picks up where it
# stopped: after a key that did not come in, and after Google ended the
# Cloud Shell session in the middle of the run. Keys that are in read
# `already`, the others are brought in.
#
# One line per key, then `Brought in and ENABLED: <n> of <n>`. A key counts
# when it has an ENABLED version and gave its public key and its signature.
# The lines and what Google gave back go into the out pack,
# ~/wallet-pairs-out-<stamp>.tgz, offered for download at the end:
#
#   results.txt          the lines
#   ring.txt             as it came
#   versions.txt         per key with an ENABLED version: the key's name
#                        and the version's full name
#   <key>.pub            the public key Google holds
#   <key>.small.sig      the key's signature of the short message
#   large.txt            the key that was asked to sign the large message
#   large.sig            its signature, or large.err with Google's answer
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
for needed in ring.txt manifest.txt msg-small.txt msg-large.bin; do
  if [ ! -s "$HERE/$needed" ]; then
    echo "The folder $HERE is not complete: $needed is missing."
    echo "Unpack the pack the Mac made first: tar xzf wallet-pairs-wrapped-<stamp>.tgz"
    exit 1
  fi
done

field() { awk -v name="$1" '$1 == name { print $2; exit }' "$HERE/ring.txt"; }
PROJECT="$(field project)"
LOCATION="$(field location)"
RING="$(field ring)"
STAMP="$(field stamp)"
for value in "$PROJECT" "$LOCATION" "$RING" "$STAMP"; do
  case "$value" in
    ''|*[!A-Za-z0-9._-]*)
      echo "ring.txt in $HERE is not understood: it must name the project, the location, the ring and the stamp."
      exit 1
      ;;
  esac
done

PARENT="projects/$PROJECT/locations/$LOCATION/keyRings/$RING"
NAME="wallet-pairs-out-$STAMP"
OUT="$(dirname "$HERE")/$NAME"
TMP="$HERE/tmp"
PACK="$HOME/$NAME.tgz"

umask 077
rm -rf "$OUT"
mkdir -p "$OUT" "$TMP"
RESULTS="$OUT/results.txt"
: > "$RESULTS"
: > "$OUT/versions.txt"
cp "$HERE/ring.txt" "$OUT/ring.txt"

say() { printf '%s\n' "$*" | tee -a "$RESULTS"; }
why() { if [ -f "$1" ]; then tr '\n' ' ' < "$1" | cut -c1-500; fi; }
size() { wc -c < "$1" 2>/dev/null | tr -d ' '; }
# Every call names the project, and none ever waits for an answer typed in.
k() { gcloud --quiet --project "$PROJECT" kms "$@"; }

version_field() {  # key, version, field
  k keys versions describe "$2" --key "$1" --keyring "$RING" --location "$LOCATION" --format="value($3)" 2>/dev/null
}

wait_version() {  # key, version: waits up to four minutes for a last state, prints it
  local state="" i
  for i in $(seq 1 60); do
    state="$(version_field "$1" "$2" state)"
    case "$state" in
      ENABLED|IMPORT_FAILED|GENERATION_FAILED|DISABLED|DESTROYED|DESTROY_SCHEDULED) break ;;
    esac
    sleep 4
  done
  printf '%s' "${state:-no answer}"
}

# What Google holds under a key's name. Sets ENABLED_VERSION, the lowest
# version that is ENABLED, and COMING_VERSION, one that is still coming in
# from a run that was cut; each empty when there is none.
look_at_key() {  # key, file for an error
  local name state rest_of_line number
  ENABLED_VERSION=""
  COMING_VERSION=""
  if ! k keys versions list --key "$1" --keyring "$RING" --location "$LOCATION" \
    --format='value(name,state)' > "$TMP/versions.list" 2>"$2"; then
    return 1
  fi
  while read -r name state rest_of_line; do
    number="${name##*/}"
    case "$number" in
      ''|*[!0-9]*) continue ;;
    esac
    case "$state" in
      ENABLED)
        if [ -z "$ENABLED_VERSION" ] || [ "$number" -lt "$ENABLED_VERSION" ]; then ENABLED_VERSION="$number"; fi
        ;;
      PENDING_IMPORT)
        COMING_VERSION="$number"
        ;;
    esac
  done < "$TMP/versions.list"
}

# Handles one key: brings its wrapped file in unless Google already holds
# an ENABLED version, then fetches the public key and a signature of the
# short message. Prints the key's one line. True when the key has an
# ENABLED version, its public key and its signature.
bring_in() {  # line number, key, import job, algorithm, wrapped file
  local step="$1" key="$2" job="$3" algorithm="$4" file="$HERE/$5"
  local err="$TMP/$2.err" how="" name="" version="" state=""
  : > "$err"
  if [ ! -f "$file" ]; then
    say "$step. $key: NOT BROUGHT IN: the wrapped file $5 is not in the pack"
    return 1
  fi

  if grep -q "/cryptoKeys/$key\$" "$TMP/keys.list"; then
    if ! look_at_key "$key" "$err"; then
      say "$step. $key: NOT BROUGHT IN: its versions could not be listed: $(why "$err")"
      return 1
    fi
    if [ -z "$ENABLED_VERSION" ] && [ -n "$COMING_VERSION" ]; then
      if [ "$(wait_version "$key" "$COMING_VERSION")" = ENABLED ]; then ENABLED_VERSION="$COMING_VERSION"; fi
    fi
    if [ -n "$ENABLED_VERSION" ]; then
      how="already"
      version="$ENABLED_VERSION"
    fi
  elif ! k keys create "$key" --keyring "$RING" --location "$LOCATION" --purpose asymmetric-signing \
    --default-algorithm "$algorithm" --protection-level software \
    --skip-initial-version-creation --import-only >/dev/null 2>"$err"; then
    say "$step. $key: NOT BROUGHT IN: the key could not be made: $(why "$err")"
    return 1
  fi

  if [ -z "$how" ]; then
    name="$(k keys versions import --import-job "$job" --keyring "$RING" --location "$LOCATION" \
      --key "$key" --algorithm "$algorithm" --wrapped-key-file "$file" --format='value(name)' 2>"$err")"
    version="${name##*/}"
    case "$version" in
      ''|*[!0-9]*)
        say "$step. $key: NOT TAKEN: $(why "$err")"
        return 1
        ;;
    esac
    state="$(wait_version "$key" "$version")"
    if [ "$state" = IMPORT_FAILED ]; then
      say "$step. $key: IMPORT_FAILED as version $version: $(version_field "$key" "$version" importFailureReason)"
      return 1
    fi
    if [ "$state" != ENABLED ]; then
      say "$step. $key: NOT ENABLED: version $version is $state"
      return 1
    fi
    how="brought in"
  fi
  printf '%s %s\n' "$key" "$PARENT/cryptoKeys/$key/cryptoKeyVersions/$version" >> "$OUT/versions.txt"

  case "$algorithm" in
    pq-*)
      # A post-quantum key: its public key in the NIST form, and a signature of the bytes themselves.
      if ! k keys versions get-public-key "$version" --key "$key" --keyring "$RING" --location "$LOCATION" \
        --public-key-format nist-pqc --output-file "$OUT/$key.pub" >/dev/null 2>"$err"; then
        say "$step. $key: $how, ENABLED as version $version; its public key: FAILED: $(why "$err")"
        return 1
      fi
      if ! k asymmetric-sign --version "$version" --key "$key" --keyring "$RING" --location "$LOCATION" \
        --input-file "$HERE/msg-small.txt" --signature-file "$OUT/$key.small.sig" >/dev/null 2>"$err"; then
        say "$step. $key: $how, ENABLED as version $version; its signature of the short message: FAILED: $(why "$err")"
        return 1
      fi
      if [ -z "$LARGE_KEY" ]; then
        LARGE_KEY="$key"
        LARGE_VERSION="$version"
      fi
      ;;
    *)
      # A P-256 key: its public key as PEM text, and a signature of the SHA-256 of the bytes.
      if ! k keys versions get-public-key "$version" --key "$key" --keyring "$RING" --location "$LOCATION" \
        --output-file "$OUT/$key.pub" >/dev/null 2>"$err"; then
        say "$step. $key: $how, ENABLED as version $version; its public key: FAILED: $(why "$err")"
        return 1
      fi
      if ! k asymmetric-sign --version "$version" --key "$key" --keyring "$RING" --location "$LOCATION" \
        --digest-algorithm sha256 --input-file "$HERE/msg-small.txt" --signature-file "$OUT/$key.small.sig" >/dev/null 2>"$err"; then
        say "$step. $key: $how, ENABLED as version $version; its signature of the short message: FAILED: $(why "$err")"
        return 1
      fi
      ;;
  esac
  if [ ! -s "$OUT/$key.pub" ] || [ ! -s "$OUT/$key.small.sig" ]; then
    say "$step. $key: $how, ENABLED as version $version; its public key or its signature came back empty"
    return 1
  fi
  say "$step. $key: $how, ENABLED as version $version; public key $(size "$OUT/$key.pub") bytes, signature $(size "$OUT/$key.small.sig") bytes"
}

say "The key ceremony, step 3 of 4, run $STAMP: project $PROJECT, location $LOCATION, key ring $RING"
say "gcloud: $(gcloud --version 2>/dev/null | head -n 1)"

# The keys the key ring holds now, in one call: a key that is not among
# them is made, every other key is looked at.
if ! k keys list --keyring "$RING" --location "$LOCATION" --format='value(name)' > "$TMP/keys.list" 2>"$TMP/keys.err"; then
  say "The keys of the key ring $RING could not be listed: $(why "$TMP/keys.err")"
  say "Stopped. Nothing was brought in."
  exit 1
fi

# One line of the manifest per key: the pair's number, the key's name, the
# import job, the algorithm, the wrapped file. The manifest is read on its
# own channel, so gcloud cannot swallow it.
LARGE_KEY=""
LARGE_VERSION=""
step=0
enabled=0
while read -r pair key job algorithm file rest_of_line <&3; do
  if [ -z "$pair" ]; then continue; fi
  step=$((step + 1))
  case "$pair$key$job$algorithm$file" in
    *[!A-Za-z0-9._-]*)
      say "$step. A line of the manifest is not understood; skipped."
      continue
      ;;
  esac
  if [ -z "$file" ]; then
    say "$step. A line of the manifest is not complete; skipped."
    continue
  fi
  if bring_in "$step" "$key" "$job" "$algorithm" "$file"; then enabled=$((enabled + 1)); fi
done 3< "$HERE/manifest.txt"

# The large message, the largest payload a validator would take, signed by
# the first ML-DSA-87 key that is in.
if [ -n "$LARGE_KEY" ]; then
  printf '%s\n' "$LARGE_KEY" > "$OUT/large.txt"
  if k asymmetric-sign --version "$LARGE_VERSION" --key "$LARGE_KEY" --keyring "$RING" --location "$LOCATION" \
    --input-file "$HERE/msg-large.bin" --signature-file "$OUT/large.sig" >/dev/null 2>"$OUT/large.err" \
    && [ -s "$OUT/large.sig" ]; then
    rm -f "$OUT/large.err"
    say "The large message ($(size "$HERE/msg-large.bin") bytes), signed by $LARGE_KEY: $(size "$OUT/large.sig") bytes"
  else
    rm -f "$OUT/large.sig"
    say "The large message ($(size "$HERE/msg-large.bin") bytes), signed by $LARGE_KEY: Google refused it: $(why "$OUT/large.err")"
  fi
else
  say "The large message: not signed, because no ML-DSA-87 key is in"
fi

say "Brought in and ENABLED: $enabled of $step"

tar -czf "$PACK" -C "$(dirname "$OUT")" "$NAME"
echo "Packed: $PACK ($(size "$PACK") bytes)"
echo
if [ "$enabled" != "$step" ]; then
  echo "Not every key is in. Paste the same line again: keys that are in read \"already\", the others are brought in."
  echo
fi
echo "Now get that file onto the Mac, into its Downloads folder. A download window should open."
echo "If none does: the three dots at the top right of Cloud Shell, Download, and type $NAME.tgz"
echo "Next, on the Mac: check.mjs (ceremony/README.md, step 4)."
if command -v cloudshell >/dev/null 2>&1; then
  cloudshell download "$PACK" || true
fi
