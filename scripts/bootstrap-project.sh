#!/bin/sh
# Prepares the Google Cloud project for the two signing servers, signer1 in
# Finland and signer2 in Frankfurt: the APIs, the service account and its
# one right, the two fixed addresses, the firewall and the two machines,
# point by point, one line printed per point. Runs in Cloud Shell, in the
# Google account that owns the project. The project is the first word and
# goes to every call: the script never acts on the project Cloud Shell
# happens to be set to. Nothing else is given and nothing is asked:
#
#   curl -fsSLO https://raw.githubusercontent.com/Anosphere/anossigningserver/main/scripts/bootstrap-project.sh && sh bootstrap-project.sh <project>
#
# Safe to run again: every point does what is still missing and answers
# "already" for what is done. Everything the commands print goes to
# ./bootstrap-project.log; the screen gets one line per point, the two
# fixed addresses, the next lines, and a last line: "done: ..." or "failed
# at step <number> (<name>): see ./bootstrap-project.log". Nothing here
# reads, makes or prints a key: the key ceremony brings the wallet pairs
# into the key ring (ceremony/README.md), and the service account made here
# may ask for a signature and nothing else.
#
# The script deletes every firewall rule of the default network but its
# own three, so it stops at its first point when the project holds a
# machine other than signer1 and signer2.
set -eu

SCRIPT=bootstrap-project.sh
LOG=./bootstrap-project.log

# The names in Google, the same on every run.
LOCATION=europe
RING=wallet-pairs
ACCOUNT=signer
TAG=signer
VM1=signer1
ZONE1=europe-north1-a
REGION1=europe-north1
ADDRESS1=signer1-ip
VM2=signer2
ZONE2=europe-west3-a
REGION2=europe-west3
ADDRESS2=signer2-ip
RULE_WALLET=signer-from-wallet
RULE_ACME=signer-acme
RULE_SSH=iap-ssh
MACHINE_TYPE=e2-small
IMAGE_FAMILY=debian-13
IMAGE_PROJECT=debian-cloud
DISK_GB=10
SCOPE=https://www.googleapis.com/auth/cloud-platform

# The two wallet servers, the only callers of port 3300, and the range
# Google's SSH tunnel comes from.
WALLET1=89.167.121.152
WALLET2=178.105.176.147
IAP_RANGE=35.235.240.0/20

# How often a call that fails is made again, and the seconds between two
# tries (patient, below): about five minutes in all.
TRIES=30
PAUSE=10

# The log holds everything a command prints; the screen, kept on fd 3, gets
# only what say() sends it.
touch "$LOG"
chmod 600 "$LOG"
exec 3>&1
exec >>"$LOG" 2>&1
printf '=== %s %s %s ===\n' "$SCRIPT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"

# say LINE: to the screen and to the log.
say() {
  printf '%s\n' "$*" >&3
  printf '%s\n' "$*"
}

# at NUMBER NAME: the point being done, for the failure line.
STEP=''
STEP_NAME=''
at() {
  STEP=$1
  STEP_NAME=$2
}

# fail REASON: the reason goes to the log, the run ends, the EXIT trap
# prints the failure line. Never called inside $(...).
fail() {
  printf '%s\n' "$*"
  exit 1
}

# arg_fail REASON: the argument check failed; nothing has been touched.
ARG_FAILED=0
arg_fail() {
  ARG_FAILED=1
  say "failed at the argument check: $*"
  exit 1
}

on_exit() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$ARG_FAILED" -eq 0 ]; then
    tail -n 5 "$LOG" >&3
    if [ -n "$STEP" ]; then
      say "failed at step $STEP ($STEP_NAME): see $LOG"
    else
      say "failed at the argument check: see $LOG"
    fi
  fi
}
trap on_exit EXIT

# matches VALUE REGEX: the whole value matches the extended regex.
matches() {
  printf '%s\n' "$1" | grep -Eq "$2"
}

# is_ipv4 VALUE: a dotted quad, four numbers 0 to 255.
is_ipv4() {
  matches "$1" '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || return 1
  ipv4_ifs=$IFS
  IFS=.
  set -- $1
  IFS=$ipv4_ifs
  for octet; do
    [ "$octet" -le 255 ] || return 1
  done
}

# has_line LINES LINE: LINE is one of the lines.
has_line() {
  printf '%s\n' "$1" | grep -Fxq "$2"
}

# g ARGS: one gcloud call. Every call names the project, and none waits
# for an answer typed in. Where Cloud Shell has the timeout command, a call
# Google leaves without an answer is ended after three minutes.
if command -v timeout >/dev/null 2>&1; then
  LIMIT='timeout 180'
else
  LIMIT=''
fi
g() {
  $LIMIT gcloud --quiet --project "$PROJECT" "$@"
}

# patient WHAT COMMAND: runs COMMAND until it succeeds. For some minutes
# after an API was switched on Google can refuse a call to it or leave it
# without an answer, and a service account can be unknown for a minute
# after it was made. So a call that fails is made again, up to TRIES times,
# PAUSE seconds apart, with one line on the screen at the first failure.
# After the last try the run ends, and the log holds Google's reason.
patient() {
  patient_what=$1
  shift
  patient_try=1
  until "$@"; do
    if [ "$patient_try" -ge "$TRIES" ]; then
      fail "$patient_what: no success in $TRIES tries"
    fi
    if [ "$patient_try" -eq 1 ]; then
      say "   $patient_what: no success yet; trying again every $PAUSE seconds, up to $TRIES times"
    fi
    patient_try=$((patient_try + 1))
    sleep "$PAUSE"
  done
}

# rules_of_default: the names of the firewall rules of the default network,
# one per line, sorted.
rules_of_default() {
  g compute firewall-rules list --filter='network ~ /networks/default$' --format='value(name)' | sort
}

# The things of the project, each made when it is missing. Each function
# answers 0 when the thing is there or was made, and sets MADE to the word
# for the line; patient runs it.

# service_account: the service account both machines sign in to Google as.
service_account() {
  if g iam service-accounts describe "$SA" --format='value(email)'; then
    MADE=already
  else
    g iam service-accounts create "$ACCOUNT" --display-name 'the signing servers signer1 and signer2' && MADE=made
  fi
}

# key_ring: the key ring of the wallet pairs.
key_ring() {
  if g kms keyrings describe "$RING" --location "$LOCATION" --format='value(name)'; then
    MADE=already
  else
    g kms keyrings create "$RING" --location "$LOCATION" && MADE=made
  fi
}

# address NAME REGION: a fixed external address.
address() {
  if g compute addresses describe "$1" --region "$2" --format='value(name)'; then
    MADE=already
  else
    g compute addresses create "$1" --region "$2" && MADE=reserved
  fi
}

# rule NAME RANGES PORT: a firewall rule of the default network that lets
# TCP on PORT in from RANGES, for the machines with the tag.
rule() {
  if g compute firewall-rules describe "$1" --format='value(name)'; then
    MADE=already
  else
    g compute firewall-rules create "$1" --network default --direction INGRESS --allow "tcp:$3" --source-ranges "$2" --target-tags "$TAG" && MADE=created
  fi
}

# machine NAME ZONE ADDRESS: a signing server's machine.
machine() {
  if g compute instances describe "$1" --zone "$2" --format='value(name)'; then
    MADE=already
  else
    g compute instances create "$1" --zone "$2" --machine-type "$MACHINE_TYPE" --image-family "$IMAGE_FAMILY" --image-project "$IMAGE_PROJECT" --boot-disk-size "${DISK_GB}GB" --network default --address "$3" --service-account "$SA" --scopes cloud-platform --tags "$TAG" --deletion-protection && MADE=made
  fi
}

# 0. The argument: the project, the one word, checked for shape before
#    anything is touched.
[ $# -ge 1 ] || arg_fail "give the project as the first word: sh $SCRIPT <project>"
PROJECT=$1
shift
[ $# -eq 0 ] || arg_fail "\"$1\" is not understood; the project is the one word: sh $SCRIPT <project>"
matches "$PROJECT" '^[a-z][a-z0-9-]{4,28}[a-z0-9]$' || arg_fail "the project must be a project id, 6 to 30 lowercase letters, digits and dashes, got \"$PROJECT\""
SA="$ACCOUNT@$PROJECT.iam.gserviceaccount.com"

# 1. The project. The APIs that are on are read once; a project that does
#    not exist, or is not this account's, ends the run here. Point 6
#    deletes firewall rules, so the run also ends here when the project
#    holds a machine that is not signer1 or signer2, each in its own zone.
#    A project whose Compute Engine API is off holds no machine.
at 1 project
ENABLED=$(g services list --enabled --format='value(config.name)')
echo '--- the APIs that are on ---'
echo "$ENABLED"
list_machines() {
  LISTED=$(g compute instances list --format='value(name,zone.basename())')
}
if has_line "$ENABLED" compute.googleapis.com; then
  patient 'the list of the machines' list_machines
  MACHINES=$(printf '%s\n' "$LISTED" | tr '\t' ' ')
  echo '--- machines ---'
  echo "$MACHINES"
  FOREIGN=$(printf '%s\n' "$MACHINES" | grep -Fxv -e "$VM1 $ZONE1" -e "$VM2 $ZONE2" -e '' | tr '\n' ',' || true)
  if [ -n "$FOREIGN" ]; then
    fail "the project $PROJECT holds a machine that is not $VM1 in $ZONE1 or $VM2 in $ZONE2: ${FOREIGN%,}. This script deletes firewall rules and is for a project that holds the two signing servers and no other machine"
  fi
  if [ -n "$MACHINES" ]; then
    say "1 project: $PROJECT, holds $(printf '%s\n' "$MACHINES" | tr '\n' ',' | sed 's/,$//; s/,/, /g') and no other machine"
  else
    say "1 project: $PROJECT, no machine yet"
  fi
else
  say "1 project: $PROJECT, no machine yet (the Compute Engine API is off)"
fi

# 2. The APIs: Compute Engine for the machines, Cloud KMS for the key ring,
#    IAM for the service account. Switching one on takes Google a minute or
#    two, and for some minutes after it the API may still refuse a call: a
#    first read of each API switched on in this run is made until it
#    answers. For Compute Engine that read is the default network, which
#    Google makes when the API is switched on.
at 2 APIs
APIS=''
SWITCHED=''
api() {
  if has_line "$ENABLED" "$1"; then
    APIS="$APIS, $2 already on"
  else
    gcloud --quiet --project "$PROJECT" services enable "$1"
    APIS="$APIS, $2 switched on"
    SWITCHED="$SWITCHED $1"
  fi
}
api compute.googleapis.com 'Compute Engine'
api cloudkms.googleapis.com 'Cloud KMS'
api iam.googleapis.com IAM
say "2 APIs: ${APIS#, }"
for api_name in $SWITCHED; do
  case $api_name in
    compute.googleapis.com) patient 'the Compute Engine API and its default network' g compute networks describe default --format='value(name)' ;;
    cloudkms.googleapis.com) patient 'the Cloud KMS API' g kms keyrings list --location "$LOCATION" --format='value(name)' ;;
    iam.googleapis.com) patient 'the IAM API' g iam service-accounts list --format='value(email)' ;;
  esac
done

# 3. The service account, one for both machines. Each machine signs in to
#    Google as this account, with no key file.
at 3 "service account $ACCOUNT"
patient "the service account $ACCOUNT" service_account
say "3 service account $ACCOUNT: $MADE ($SA)"

# 4. The key ring, made when missing (the key ceremony normally made it),
#    and on it the service account's one right: roles/cloudkms.signer,
#    which lets it ask for a signature and never read, make or destroy a
#    key. Set on every run: the binding is idempotent.
at 4 "key ring $RING"
patient "the key ring $RING" key_ring
RING_MADE=$MADE
patient "the right of $ACCOUNT on the key ring $RING" g kms keyrings add-iam-policy-binding "$RING" --location "$LOCATION" --member "serviceAccount:$SA" --role roles/cloudkms.signer
say "4 key ring $RING in $LOCATION: $RING_MADE; roles/cloudkms.signer for $SA"

# 5. The two fixed addresses, one per machine, each in its machine's
#    region. The wallet's list of signing servers and each machine's
#    certificate name them.
at 5 'fixed addresses'
patient "the address $ADDRESS1" address "$ADDRESS1" "$REGION1"
MADE1=$MADE
IP1=$(g compute addresses describe "$ADDRESS1" --region "$REGION1" --format='value(address)')
is_ipv4 "$IP1" || fail "the address $ADDRESS1 in $REGION1 reads \"$IP1\", not an IPv4 address"
patient "the address $ADDRESS2" address "$ADDRESS2" "$REGION2"
MADE2=$MADE
IP2=$(g compute addresses describe "$ADDRESS2" --region "$REGION2" --format='value(address)')
is_ipv4 "$IP2" || fail "the address $ADDRESS2 in $REGION2 reads \"$IP2\", not an IPv4 address"
say "5 fixed addresses: $ADDRESS1 $IP1 $MADE1, $ADDRESS2 $IP2 $MADE2"

# 6. The firewall of the default network: the three rules of ours, each
#    created when missing, then every other rule of that network deleted,
#    in one delete. Port 3300 is open to the two wallet servers only, port
#    80 to everyone for the certificate's renewal, and port 22 to Google's
#    SSH tunnel only.
at 6 firewall
patient "the firewall rule $RULE_WALLET" rule "$RULE_WALLET" "$WALLET1/32,$WALLET2/32" 3300
FIREWALL="$RULE_WALLET $MADE"
patient "the firewall rule $RULE_ACME" rule "$RULE_ACME" 0.0.0.0/0 80
FIREWALL="$FIREWALL, $RULE_ACME $MADE"
patient "the firewall rule $RULE_SSH" rule "$RULE_SSH" "$IAP_RANGE" 22
FIREWALL="$FIREWALL, $RULE_SSH $MADE"
RULES=$(rules_of_default)
OTHERS=''
DELETED=''
for rule_name in $RULES; do
  case $rule_name in
    "$RULE_WALLET"|"$RULE_ACME"|"$RULE_SSH") ;;
    *)
      OTHERS="$OTHERS $rule_name"
      DELETED="$DELETED, $rule_name"
      ;;
  esac
done
if [ -n "$OTHERS" ]; then
  g compute firewall-rules delete $OTHERS
  say "6 firewall: $FIREWALL; deleted ${DELETED#, }"
else
  say "6 firewall: $FIREWALL; no other rules"
fi

# 7. The two machines: e2-small, Debian 13, a 10 GB boot disk, the fixed
#    address, the service account with the cloud-platform scope (the
#    account's rights decide what a machine may do, and it has the one),
#    the tag the firewall rules select by, and Google's deletion
#    protection.
at 7 machines
patient "the machine $VM1" machine "$VM1" "$ZONE1" "$IP1"
MADE1=$MADE
patient "the machine $VM2" machine "$VM2" "$ZONE2" "$IP2"
MADE2=$MADE
say "7 machines: $VM1 in $ZONE1 $MADE1, $VM2 in $ZONE2 $MADE2"

# 8. Look again: everything the points above decide on, read back;
#    anything that differs ends the run naming it.
at 8 'look again'
DIFF=''
differs() {
  DIFF="$DIFF; $*"
}
# check_rule NAME LINE [LINE]: the rule reads as one of the lines: its
# direction, where it lets in from, the tag, the port.
check_rule() {
  rule_name=$1
  shift
  rule_line=$(g compute firewall-rules describe "$rule_name" --format='value(direction,sourceRanges.list(),targetTags.list(),allowed[].map().firewall_rule().list())' | tr '\t' ' ')
  echo "--- rule $rule_name --- $rule_line"
  for rule_expected; do
    if [ "$rule_line" = "$rule_expected" ]; then
      return 0
    fi
  done
  differs "the firewall rule $rule_name reads \"$rule_line\", not \"$1\""
}
# check_machine NAME ZONE ADDRESS: the machine reads as point 7 makes it.
# A machine made a moment ago gets up to a minute to be running.
check_machine() {
  machine_expected="RUNNING $MACHINE_TYPE $3 $SA $SCOPE $TAG True $DISK_GB"
  machine_try=1
  while :; do
    machine_line=$(g compute instances describe "$1" --zone "$2" --format='value(status,machineType.basename(),networkInterfaces[0].accessConfigs[0].natIP,serviceAccounts[0].email,serviceAccounts[0].scopes,tags.items,deletionProtection,disks[0].diskSizeGb)' | tr '\t' ' ')
    case $machine_line in
      PROVISIONING*|STAGING*) ;;
      *) break ;;
    esac
    if [ "$machine_try" -ge 12 ]; then
      break
    fi
    machine_try=$((machine_try + 1))
    sleep 5
  done
  echo "--- machine $1 --- $machine_line"
  [ "$machine_line" = "$machine_expected" ] || differs "the machine $1 reads \"$machine_line\", not \"$machine_expected\" (its state, its type, its address, its service account, its scope, its tag, deletion protection, its disk in GB)"
}
READ_SA=$(g iam service-accounts describe "$SA" --format='value(email)')
echo "--- service account --- $READ_SA"
[ "$READ_SA" = "$SA" ] || differs "the service account reads \"$READ_SA\", not $SA"
POLICY=$(g kms keyrings get-iam-policy "$RING" --location "$LOCATION" --flatten='bindings[].members' --format='value(bindings.role,bindings.members)')
POLICY=$(printf '%s\n' "$POLICY" | tr '\t' ' ')
echo "--- the rights on the key ring $RING ---"
echo "$POLICY"
has_line "$POLICY" "roles/cloudkms.signer serviceAccount:$SA" || differs "the key ring $RING does not show roles/cloudkms.signer for $SA"
RULES=$(rules_of_default)
echo '--- firewall rules of the default network ---'
echo "$RULES"
EXPECTED_RULES=$(printf '%s\n' "$RULE_WALLET" "$RULE_ACME" "$RULE_SSH" | sort)
[ "$RULES" = "$EXPECTED_RULES" ] || differs "the firewall rules of the default network are $(printf '%s' "$RULES" | tr '\n' ' '), not exactly $(printf '%s' "$EXPECTED_RULES" | tr '\n' ' ')"
check_rule "$RULE_WALLET" "INGRESS $WALLET1/32,$WALLET2/32 $TAG tcp:3300" "INGRESS $WALLET2/32,$WALLET1/32 $TAG tcp:3300"
check_rule "$RULE_ACME" "INGRESS 0.0.0.0/0 $TAG tcp:80"
check_rule "$RULE_SSH" "INGRESS $IAP_RANGE $TAG tcp:22"
check_machine "$VM1" "$ZONE1" "$IP1"
check_machine "$VM2" "$ZONE2" "$IP2"
if [ -n "$DIFF" ]; then
  fail "look again: ${DIFF#; }"
fi
say '8 look again: ok'

# 9. Cloud Shell's SSH key, made now so the first gcloud compute ssh asks
#    nothing.
at 9 'ssh key'
SSH_KEY="${HOME:?HOME is not set}/.ssh/google_compute_engine"
if [ -f "$SSH_KEY" ]; then
  say '9 ssh key: already'
else
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"
  ssh-keygen -q -t rsa -b 3072 -N '' -f "$SSH_KEY"
  say '9 ssh key: made'
fi

# 10. The budget is a Console page; nothing is made here.
at 10 budget
say "10 budget: a Console page, nothing is made here (Billing, Budgets & alerts, Create budget, for the project $PROJECT)"

# What leaves this script, and the next lines.
say 'The two fixed addresses:'
say "  $VM1  $IP1"
say "  $VM2  $IP2"
say 'Next, for each machine: SSH to it from Cloud Shell, then its line on the machine:'
say "  gcloud compute ssh $VM1 --zone $ZONE1 --tunnel-through-iap --project $PROJECT"
say "  curl -fsSLO https://raw.githubusercontent.com/Anosphere/anossigningserver/main/scripts/bootstrap-vm.sh && sudo sh bootstrap-vm.sh --ip $IP1 --email <your email>"
say "  gcloud compute ssh $VM2 --zone $ZONE2 --tunnel-through-iap --project $PROJECT"
say "  curl -fsSLO https://raw.githubusercontent.com/Anosphere/anossigningserver/main/scripts/bootstrap-vm.sh && sudo sh bootstrap-vm.sh --ip $IP2 --email <your email>"
say "done: project $PROJECT is ready for $VM1 and $VM2"
