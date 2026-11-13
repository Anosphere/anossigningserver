#!/bin/sh
# Puts the files of deploy/ in place and starts or reloads what reads
# them. Run as root from the repo root:
#
#   sh scripts/install-system-files.sh
#
# Safe to repeat; run again after any pull that touched deploy/.
#
# On signing1 that is deploy/signingserver.service alone: the unit is
# installed, enabled and restarted. The key file, keys.json, must exist
# before the first run (the deploy plan, 4.3): the unit cannot write it.
#
# On signer1 and signer2, which alone have the file /etc/signingserver/env
# (scripts/bootstrap-vm.sh writes it), nginx comes after the unit: the
# folder for the certificate, the ACME folder, the port 80 site, and the
# TLS site once the certificate exists at /etc/signingserver/tls. So the
# script runs twice at setup, before and after acme.sh issues the
# certificate; scripts/bootstrap-vm.sh does both.
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

# The rest is for signer1 and signer2 alone.
if [ -f /etc/signingserver/env ]; then
  TLS=/etc/signingserver/tls

  # The ACME folder and the folder for the certificate. The key file is
  # created empty and owner-only before any certificate exists, so
  # acme.sh's key lands in a file that is already 0600.
  mkdir -p /var/www/acme/.well-known/acme-challenge "$TLS"
  chmod 755 "$TLS"
  if [ ! -e "$TLS/key.pem" ]; then
    touch "$TLS/key.pem"
    chmod 600 "$TLS/key.pem"
  fi

  # nginx: Debian's default site goes; the port 80 site always; the TLS
  # site once both certificate files are non-empty.
  rm -f /etc/nginx/sites-enabled/default
  install -m 0644 "$REPO/deploy/nginx/signer-acme.conf" /etc/nginx/sites-available/signer-acme
  ln -sf /etc/nginx/sites-available/signer-acme /etc/nginx/sites-enabled/signer-acme
  if [ -s "$TLS/fullchain.pem" ] && [ -s "$TLS/key.pem" ]; then
    install -m 0644 "$REPO/deploy/nginx/signer.conf" /etc/nginx/sites-available/signer
    ln -sf /etc/nginx/sites-available/signer /etc/nginx/sites-enabled/signer
    tls_site=installed
  else
    tls_site=skipped
  fi
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  echo "Installed the nginx sites signer-acme and signer (TLS site: $tls_site); nginx was reloaded"
  if [ "$tls_site" = skipped ]; then
    echo "The TLS site is skipped until the certificate is at $TLS; issue it, then run this script again."
  fi
fi
