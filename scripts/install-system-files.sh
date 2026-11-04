#!/bin/sh
# Puts deploy/signingserver.service in place on signing1 and starts or
# restarts the unit. Run as root from the repo root:
#
#   sh scripts/install-system-files.sh
#
# Safe to repeat; run again after any pull that touched deploy/. The key
# file, keys.json, must exist before the first run (the deploy plan, 4.3):
# the unit cannot write it.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sh scripts/install-system-files.sh" >&2
  exit 1
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -f "$REPO/deploy/signingserver.service" ]; then
  echo "deploy/ not found at $REPO; run this script from the signingserver checkout" >&2
  exit 1
fi

install -m 0644 "$REPO/deploy/signingserver.service" /etc/systemd/system/signingserver.service
systemctl daemon-reload
systemctl enable signingserver
systemctl restart signingserver
echo "Installed signingserver.service; the server was restarted: journalctl -fu signingserver"
