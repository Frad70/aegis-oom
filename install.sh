#!/usr/bin/env bash
# install.sh: build and install aegis-oom and aegis-reaper as system services. Idempotent.
# Requires root. PREFIX (default /usr/local) sets where binaries and docs go.
set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
DOCDIR="$PREFIX/share/doc/aegis-oom"
CONFDIR=/etc/aegis
UNITDIR=/etc/systemd/system

[ "$(id -u)" = 0 ] || { echo "Root is required: sudo $0"; exit 1; }
case "$PREFIX" in /*) ;; *) echo "PREFIX must be an absolute path"; exit 1 ;; esac

echo "[1/5] Building aegis-reaper"
if cc -O2 -Wall -Wextra -std=c11 -static -o "$SRC/aegis-reaper" "$SRC/reaper.c" "$SRC/oom_policy.c" 2>/dev/null; then
  echo "      static binary (survives a broken libc)"
else
  make -C "$SRC" -B aegis-reaper
  echo "      dynamic binary (static libc is not available)"
fi

echo "[2/5] Building aegis-oom"
make -C "$SRC" -B aegis-oom

install_binary() {
  install -m 0755 "$1" "$2.new"
  mv -fT "$2.new" "$2"
}

echo "[3/5] Installing files to $PREFIX"
mkdir -p "$BINDIR" "$DOCDIR"
install_binary "$SRC/aegis-reaper" "$BINDIR/aegis-reaper"
install_binary "$SRC/aegis-oom" "$BINDIR/aegis-oom"
install -m 0644 "$SRC/README.md" "$DOCDIR/README.md"

echo "[4/5] Installing the config to $CONFDIR (an existing config is kept)"
mkdir -p "$CONFDIR"
if [ -f "$CONFDIR/aegis-oom.conf" ]; then
  install -m 0644 "$SRC/aegis-oom.conf" "$CONFDIR/aegis-oom.conf.default"
  echo "      Kept the existing config; the new default is aegis-oom.conf.default"
else
  install -m 0644 "$SRC/aegis-oom.conf" "$CONFDIR/aegis-oom.conf"
fi

echo "[5/5] Installing systemd units and restarting the services"
for unit in aegis-reaper.service aegis-oom.service; do
  sed "s|@PREFIX@|$PREFIX|g" "$SRC/systemd/$unit" > "$UNITDIR/$unit.new"
  chmod 0644 "$UNITDIR/$unit.new"
  mv -fT "$UNITDIR/$unit.new" "$UNITDIR/$unit"
done
systemctl daemon-reload
systemctl enable aegis-reaper.service aegis-oom.service >/dev/null 2>&1
# restart, not enable --now: on an upgrade the old binary would keep running
systemctl restart aegis-reaper.service
systemctl restart aegis-oom.service

echo
systemctl --no-pager --lines=0 status aegis-reaper.service aegis-oom.service 2>/dev/null \
  | grep -E "aegis|Active:" || true
echo
if grep -qE '^[[:space:]]*AEG_OOM_DRYRUN=0' "$CONFDIR/aegis-oom.conf" 2>/dev/null; then
  echo "  OOM mode:  live (AEG_OOM_DRYRUN=0), aegis-oom kills processes"
else
  echo "  OOM mode:  dry run (AEG_OOM_DRYRUN=1); check /run/aegis/oom.state, then set 0 in the config"
fi
echo "  Logs:      journalctl -u aegis-oom -u aegis-reaper -f"
echo "  Config:    $CONFDIR/aegis-oom.conf (after editing: systemctl reload aegis-oom aegis-reaper)"
echo "  Uninstall: sudo PREFIX=$PREFIX $SRC/uninstall.sh"
