#!/bin/sh
# Sets up one of the two signing servers, signer1 or signer2, point by
# point, one line printed per point, and on every later run pulls the repo
# and restarts the server when the pull brought something. Runs on the
# machine as root, over SSH from Cloud Shell; every value is a flag and
# nothing is asked:
#
#   curl -fsSLO https://raw.githubusercontent.com/Anosphere/anossigningserver/main/scripts/bootstrap-vm.sh && sudo sh bootstrap-vm.sh --ip <the machine's fixed address> --email <your email>
#
# Safe to run again: every point does what is still missing and answers
# "already" for what is done, then the repo is pulled. Once a value is on
# the machine its flag may be left out, so every later run is the same line
# with nothing after bootstrap-vm.sh; a flag that is given must match what
# the machine has. When the pull brought nothing, nothing is restarted.
# Everything the commands print goes to
# /var/log/signingserver-bootstrap.log; the screen gets one line per point
# and a last line: "done: ..." or "failed at step <number> (<name>): see
# /var/log/signingserver-bootstrap.log". Nothing here reads or prints a
# key: the wallet pairs stay in Google Cloud KMS, and the TLS key is
# acme.sh's and nginx's.
set -eu

SCRIPT=bootstrap-vm.sh
LOG=/var/log/signingserver-bootstrap.log
REPO=/opt/signingserver/signingserver
INSTALL=$REPO/scripts/install-system-files.sh
LIST=$REPO/network/wallet-pairs.json
ENV_FILE=/etc/signingserver/env
TLS=/etc/signingserver/tls
ACME=/root/.acme.sh/acme.sh
METADATA=http://169.254.169.254/computeMetadata/v1

# The server listens on 127.0.0.1:PORT, and nginx hands it what comes in
# over TLS on TLS_PORT. Both numbers are also in deploy/nginx/signer.conf.
PORT=8300
TLS_PORT=3300
# The three lines of /etc/signingserver/env, which the unit reads.
ENV_LINES="KEY_STORE=kms
PORT=$PORT
HOST=127.0.0.1"
# How many seconds the server gets to print its boot check line. The boot
# check asks Google once per wallet pair before the server listens.
BOOT_WAIT=300

# 0. Root first: the log and everything below need it.
if [ "$(id -u)" -ne 0 ]; then
  echo "failed at the argument check: run as root: sudo sh $SCRIPT --ip <the machine's fixed address> --email <your email>" >&2
  exit 1
fi
# acme.sh keeps its files under root's home; apt asks nothing.
HOME=/root
export HOME
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

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

TMP=''
on_exit() {
  status=$?
  if [ -n "$TMP" ]; then
    rm -rf "$TMP"
  fi
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

# metadata PATH: one value from the metadata server; fails on a 404.
metadata() {
  curl -sS -f -H 'Metadata-Flavor: Google' "$METADATA/$1"
}

# as_signingserver COMMAND: through the signingserver user's login shell.
as_signingserver() {
  sudo -iu signingserver bash -c "$1"
}

# git_signingserver ARGS: a git command in the repo, as its owner, output
# kept clean of a login shell's for capture.
git_signingserver() {
  sudo -u signingserver git -C "$REPO" "$@"
}

# installed PACKAGE: dpkg says so.
installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed'
}

# node_is_24: node -v starts with v24.
node_is_24() {
  case $(node -v 2>/dev/null || true) in
    v24.*) return 0 ;;
  esac
  return 1
}

# cert_end: the chain's notAfter, as openssl prints it.
cert_end() {
  openssl x509 -noout -enddate -in "$TLS/fullchain.pem" | sed 's/^notAfter=//'
}

# server_state: active, activating, inactive, failed, ...
server_state() {
  systemctl is-active signingserver || true
}

# server_run: the server's current run, its systemd invocation. Every
# start of the unit is a new one.
server_run() {
  systemctl show -p InvocationID --value signingserver || true
}

# run_log RUN: the journal of that run alone, so a line from an earlier
# boot is never read.
run_log() {
  journalctl "_SYSTEMD_INVOCATION_ID=$1" --no-pager -o cat
}

# wait_server: waits for the boot check line of the server's current run,
# "boot check: ..." or "boot check failed: ..."; sets BOOT_LINE. The boot
# check asks Google once per pair before the server listens, so the line
# comes some seconds after the start. The wait has three ends besides the
# good line. A "boot check failed" line ends the run with it. A start
# that ended with neither line ends the run with the error of that start:
# a list the server refuses stops it before the boot check, and systemd
# then starts it again every 5 seconds, forever. And BOOT_WAIT seconds
# without a line end the run.
wait_server() {
  run=$(server_run)
  waited=0
  while :; do
    BOOT_LINE=$(run_log "$run" | grep -E '^boot check' | tail -n 1)
    if [ -n "$BOOT_LINE" ]; then
      break
    fi
    if [ "$(server_state)" != active ] || [ "$(server_run)" != "$run" ]; then
      # That start is over. Its last lines may still be on their way into
      # the journal: one more look, a second later.
      sleep 1
      BOOT_LINE=$(run_log "$run" | grep -E '^boot check' | tail -n 1)
      break
    fi
    if [ "$waited" -ge "$BOOT_WAIT" ]; then
      fail "the server printed no boot check line in $BOOT_WAIT seconds and is $(server_state): journalctl -u signingserver"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  case $BOOT_LINE in
    'boot check failed'*) fail "$BOOT_LINE" ;;
    '')
      cause=$(run_log "$run" | grep -E '^[A-Za-z]*Error' | head -n 1)
      if [ -z "$cause" ]; then
        cause='no line that starts with Error in that start: journalctl -u signingserver'
      fi
      earlier=$(journalctl -u signingserver -n 200 --no-pager -o cat | grep -E '^boot check failed' | tail -n 1)
      if [ -n "$earlier" ]; then
        cause="$cause; the last boot check failed line of the journal: $earlier"
      fi
      fail "the server is $(server_state) and its last start ended before the boot check: $cause"
      ;;
  esac
  [ "$(server_state)" = active ] || fail "the server is $(server_state) after its boot check: journalctl -u signingserver"
}

# ask_health: one question to the server's own port, with no nginx
# between; sets HEALTH_CODE and, on a 200, HEALTH_STORE, HEALTH_PAIRS and
# HEALTH_LINE.
ask_health() {
  HEALTH_CODE=$(curl -s -o "$TMP/health.json" -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
  [ "$HEALTH_CODE" = 200 ] || return 1
  parsed=$(node -e 'const h = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); console.log([h.status, h.keyStore, h.pairs].join("|"));' "$TMP/health.json") || return 1
  health_ifs=$IFS
  IFS='|'
  set -- $parsed
  IFS=$health_ifs
  HEALTH_STORE=${2:-}
  HEALTH_PAIRS=${3:-}
  HEALTH_LINE="health 200 ${1:-}, key store $HEALTH_STORE, $HEALTH_PAIRS pairs"
}

# health: up to ten seconds for the server's own 200.
health() {
  waited=0
  until ask_health; do
    if [ "$waited" -ge 10 ]; then
      fail "http://127.0.0.1:$PORT/health answers $HEALTH_CODE after 10 seconds (000 is no answer at all): journalctl -u signingserver"
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

# server_check RESTARTED: the server's boot check line and its health,
# after a restart in this run (RESTARTED 1) or as the server runs now (0).
# A server that already answers is not waited for. Sets SERVER_LINE.
server_check() {
  if [ "$1" -eq 0 ] && ask_health; then
    # A server up for weeks may have its boot line rotated out of the
    # journal; the health answer carries the same count.
    BOOT_LINE=$(run_log "$(server_run)" | grep -E '^boot check' | tail -n 1)
    case $BOOT_LINE in
      '') BOOT_LINE='boot line no longer in the journal' ;;
    esac
    SERVER_LINE="already up, $BOOT_LINE; $HEALTH_LINE"
  else
    wait_server
    health
    SERVER_LINE="up, $BOOT_LINE; $HEALTH_LINE"
  fi
}

# 0. The arguments: named flags, each given once, each checked for shape,
#    then against the machine and the metadata server, before anything is
#    touched.
IP=''
EMAIL=''
SEEN=''
while [ $# -gt 0 ]; do
  case $1 in
    --ip|--email) ;;
    *) arg_fail "unknown flag \"$1\"; the flags are --ip and --email" ;;
  esac
  [ $# -ge 2 ] || arg_fail "$1 needs a value"
  case " $SEEN " in
    *" $1 "*) arg_fail "$1 given twice" ;;
  esac
  SEEN="$SEEN $1"
  case $1 in
    --ip) IP=$2 ;;
    --email) EMAIL=$2 ;;
  esac
  shift 2
done
case " $SEEN " in
  *" --ip "*)
    is_ipv4 "$IP" || arg_fail "--ip must be a dotted quad, four numbers 0 to 255, got \"$IP\""
    ;;
esac
case " $SEEN " in
  *" --email "*)
    matches "$EMAIL" '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' || arg_fail "--email must be an address with one @ and a dot after it, got \"$EMAIL\""
    ;;
esac

# This VM, from the metadata server.
VM_NAME=$(metadata instance/name) || arg_fail 'cannot read the metadata server at 169.254.169.254: is this a Compute Engine VM?'
case $VM_NAME in
  signer1|signer2) ;;
  *) arg_fail "this VM is $VM_NAME, not signer1 or signer2" ;;
esac
VM_IP=$(metadata instance/network-interfaces/0/access-configs/0/external-ip || true)
[ -n "$VM_IP" ] || arg_fail 'this VM has no external address; a signing server holds a fixed one (scripts/bootstrap-project.sh, point 5)'

# --ip against the VM, --email against acme.sh's account; a value left out
# is taken from there.
if [ -n "$IP" ]; then
  [ "$IP" = "$VM_IP" ] || arg_fail "--ip is $IP, but Google's metadata says this VM's external address is $VM_IP"
elif [ -s "$TLS/fullchain.pem" ]; then
  IP=$VM_IP
else
  arg_fail "--ip is required until the certificate exists at $TLS/fullchain.pem: the machine's fixed address"
fi
if [ -n "$EMAIL" ]; then
  if [ -f "$ACME" ] && [ -f /root/.acme.sh/account.conf ]; then
    DISK_EMAIL=$(sed -n 's/^ACCOUNT_EMAIL=//p' /root/.acme.sh/account.conf | head -n 1 | tr -d "'\"")
    if [ -n "$DISK_EMAIL" ] && [ "$EMAIL" != "$DISK_EMAIL" ]; then
      arg_fail "--email is $EMAIL, but acme.sh was installed with $DISK_EMAIL"
    fi
  fi
elif [ ! -f "$ACME" ]; then
  arg_fail "--email is required until acme.sh is installed at $ACME: where Let's Encrypt writes about the certificate"
fi

TMP=$(mktemp -d)
if [ -d "$REPO/.git" ]; then
  REPO_EXISTED=1
else
  REPO_EXISTED=0
fi
# Whether any point did work in this run, for the done line, and whether
# the server was restarted in this run, for point 8.
WORK=0
RESTARTED=0

# 1. Look first: Debian 13 is required; unattended upgrades are reported.
at 1 look
DEBIAN=$(cat /etc/debian_version)
case $DEBIAN in
  13|13.*) ;;
  *) fail "this VM runs Debian $DEBIAN; a signing server runs Debian 13" ;;
esac
UPGRADES=$(systemctl is-active unattended-upgrades || true)
say "1 look: $VM_NAME, Debian $DEBIAN, unattended-upgrades $UPGRADES"

# 2. Packages: nginx, git and curl from Debian 13, Node 24 from NodeSource.
at 2 packages
if node_is_24 && installed nginx && installed git && installed curl; then
  PACKAGES=already
else
  apt-get update
  apt-get install -y nginx git curl
  curl -fsSL https://deb.nodesource.com/setup_24.x -o "$TMP/nodesource-setup.sh"
  bash "$TMP/nodesource-setup.sh"
  apt-get install -y nodejs
  node_is_24 || fail "node is \"$(node -v 2>&1 || true)\" after the install, not v24"
  PACKAGES=installed
  WORK=1
fi
NODE_V=$(node -v)
NGINX_V=$(/usr/sbin/nginx -v 2>&1 | sed 's/^nginx version: nginx\///')
say "2 packages: node $NODE_V, nginx $NGINX_V, git, curl $PACKAGES"

# 3. The signingserver user, the repo under its home, its dependencies.
#    The list of the wallet pairs, network/wallet-pairs.json, is written
#    by the key ceremony and committed: without it the run stops here,
#    before anything is installed. A clone left by such a run is pulled
#    once more first, so the same line goes on once the list is pushed.
at 3 'user and repo'
if id signingserver; then
  USER_LINE='signingserver already'
else
  useradd --system --create-home --home-dir /opt/signingserver --shell /bin/bash signingserver
  USER_LINE='signingserver created'
  WORK=1
fi
if [ -d "$REPO/.git" ]; then
  REPO_LINE='repo already'
  if [ ! -f "$LIST" ]; then
    as_signingserver "git -C $REPO pull --ff-only"
    REPO_LINE='repo already, pulled for the list'
  fi
else
  as_signingserver "git clone https://github.com/Anosphere/anossigningserver.git $REPO"
  REPO_LINE='repo cloned'
  WORK=1
fi
[ -f "$LIST" ] || fail "the clone has no network/wallet-pairs.json: the key ceremony comes first. Commit and push the list it writes, then run this line again"
if [ -d "$REPO/node_modules/@google-cloud/kms" ]; then
  NPM_LINE='npm ci already'
else
  as_signingserver "cd $REPO && npm ci"
  NPM_LINE='npm ci run'
  WORK=1
fi
say "3 user and repo: $USER_LINE, $REPO_LINE, $NPM_LINE"

# 4. The env file the unit reads: the key store in Google Cloud KMS, and
#    the server on 127.0.0.1 behind nginx. The install script takes this
#    file as the sign of a Google machine.
at 4 'env file'
if [ -f "$ENV_FILE" ]; then
  [ "$(cat "$ENV_FILE")" = "$ENV_LINES" ] || fail "$ENV_FILE does not hold exactly the three lines KEY_STORE=kms, PORT=$PORT and HOST=127.0.0.1"
  say "4 env file: $ENV_FILE already"
else
  mkdir -p /etc/signingserver
  printf '%s\n' "$ENV_LINES" > "$ENV_FILE"
  chmod 644 "$ENV_FILE"
  WORK=1
  say "4 env file: $ENV_FILE written (KEY_STORE=kms, PORT=$PORT, HOST=127.0.0.1)"
fi

# 5. System files, first pass: the unit, the folder for the certificate,
#    the ACME folder, nginx on port 80. Run when any of its products is
#    missing. It starts the server, which then asks Google for the first
#    time.
at 5 'system files, first pass'
missing_product() {
  for product in /etc/systemd/system/signingserver.service /etc/nginx/sites-enabled/signer-acme "$TLS"; do
    [ -e "$product" ] || return 0
  done
  return 1
}
if missing_product; then
  sh "$INSTALL"
  FIRST_PASS=installed
  RESTARTED=1
  WORK=1
else
  FIRST_PASS=already
fi
say "5 system files, first pass: $FIRST_PASS"

# 6. The certificate: acme.sh 3.1.6 from a git clone, Let's Encrypt, an IP
#    certificate on the shortlived profile, installed for nginx with the
#    reload command acme.sh's daily cron runs at every renewal.
at 6 certificate
if [ -s "$TLS/fullchain.pem" ]; then
  say "6 certificate: already, valid to $(cert_end)"
else
  if [ ! -f "$ACME" ]; then
    if [ ! -f /root/acme.sh-src/acme.sh ]; then
      git clone --depth 1 --branch 3.1.6 https://github.com/acmesh-official/acme.sh.git /root/acme.sh-src
    fi
    (cd /root/acme.sh-src && ./acme.sh --install -m "$EMAIL")
  fi
  "$ACME" --set-default-ca --server letsencrypt
  # Exit code 2 is acme.sh's "skipping, not due": a certificate issued by
  # an earlier run that stopped before the install step is in its store.
  issue_status=0
  "$ACME" --issue --server letsencrypt -d "$IP" -w /var/www/acme --cert-profile shortlived --days 3 || issue_status=$?
  case $issue_status in
    0|2) ;;
    *) fail "acme.sh --issue for $IP exited $issue_status" ;;
  esac
  "$ACME" --install-cert -d "$IP" --ecc --key-file "$TLS/key.pem" --fullchain-file "$TLS/fullchain.pem" --reloadcmd "chmod 600 $TLS/key.pem && systemctl reload nginx"
  [ -s "$TLS/fullchain.pem" ] || fail "no certificate at $TLS/fullchain.pem after acme.sh --install-cert"
  WORK=1
  say "6 certificate: issued for $IP, valid to $(cert_end)"
fi

# 7. System files, second pass, which installs the TLS site now that the
#    certificate exists, and restarts the server.
at 7 'system files, second pass'
if [ -e /etc/nginx/sites-enabled/signer ]; then
  SECOND_PASS='TLS site already'
else
  sh "$INSTALL"
  [ -e /etc/nginx/sites-enabled/signer ] || fail 'no TLS site at /etc/nginx/sites-enabled/signer after the install script'
  SECOND_PASS='TLS site installed'
  RESTARTED=1
  WORK=1
fi
say "7 system files, second pass: $SECOND_PASS"

# 8. The server: its boot check line, the unit active, its own health.
at 8 'the server'
server_check "$RESTARTED"
say "8 the server: $SERVER_LINE"

# 9. The certificate as the world sees it: curl connects to the local port
#    but checks the chain and the name against the address in the URL, and
#    the answer comes from the server through nginx.
at 9 'certificate as the world sees it'
WORLD=$(curl -sS -o /dev/null -w '%{http_code}' --connect-to "$IP:$TLS_PORT:127.0.0.1:$TLS_PORT" "https://$IP:$TLS_PORT/health") || fail "curl could not verify the certificate for $IP"
[ "$WORLD" = 200 ] || fail "https://$IP:$TLS_PORT/health through 127.0.0.1 answers $WORLD, not 200"
say "9 certificate as the world sees it: valid for $IP to $(cert_end)"

# 10. Pull and restart, on every run after the first: new software or a
#     new list of pairs; npm ci when the lock file changed, the install
#     script when deploy/ or itself changed (it restarts the server), else
#     a plain restart; then point 8 again. A pull that brought nothing
#     restarts nothing.
HEAD_MOVED=0
if [ "$REPO_EXISTED" -eq 1 ]; then
  at 10 'pull and restart'
  OLD_HEAD=$(git_signingserver rev-parse --short HEAD)
  as_signingserver "git -C $REPO pull --ff-only"
  NEW_HEAD=$(git_signingserver rev-parse --short HEAD)
  if [ "$OLD_HEAD" != "$NEW_HEAD" ]; then
    HEAD_MOVED=1
    CHANGED=$(git_signingserver diff --name-only "$OLD_HEAD" "$NEW_HEAD")
    PULL_LINE="Fast-forward to $NEW_HEAD"
    if has_line "$CHANGED" package-lock.json; then
      as_signingserver "cd $REPO && npm ci"
      PULL_LINE="$PULL_LINE, npm ci run"
    fi
    if printf '%s\n' "$CHANGED" | grep -Eq '^(deploy/|scripts/install-system-files\.sh$)'; then
      sh "$INSTALL"
      PULL_LINE="$PULL_LINE, system files installed, restarted"
    else
      systemctl restart signingserver
      PULL_LINE="$PULL_LINE, restarted"
    fi
    server_check 1
    say "10 pull and restart: $PULL_LINE; $SERVER_LINE"
  else
    say "10 pull and restart: already up to date ($NEW_HEAD), nothing restarted"
  fi
fi

HEAD=$(git_signingserver rev-parse --short HEAD)
if [ "$HEAD_MOVED" -eq 1 ]; then
  say "done: $VM_NAME runs $HEAD, key store $HEALTH_STORE, $HEALTH_PAIRS pairs"
elif [ "$WORK" -eq 1 ]; then
  say "done: $VM_NAME is up at https://$IP:$TLS_PORT on $HEAD, key store $HEALTH_STORE, $HEALTH_PAIRS pairs; only the two wallet servers can reach it"
else
  say "done: the pull brought nothing and nothing was restarted; $VM_NAME runs $HEAD, key store $HEALTH_STORE, $HEALTH_PAIRS pairs, certificate valid to $(cert_end)"
fi
