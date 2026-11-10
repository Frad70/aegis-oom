#!/usr/bin/env bash
# uninstall.sh: remove aegis-oom and aegis-reaper. The config is kept unless --purge is given.
set -uo pipefail
PREFIX="${PREFIX:-/usr/local}"
UNITDIR=/etc/systemd/system
[ "$(id -u)" = 0 ] || { echo "Root is required: sudo $0"; exit 1; }

systemctl disable --now aegis-reaper.service aegis-oom.service 2>/dev/null || true
rm -f "$UNITDIR/aegis-reaper.service" "$UNITDIR/aegis-oom.service"
systemctl daemon-reload

rm -f "$PREFIX/bin/aegis-oom" "$PREFIX/bin/aegis-reaper" "$PREFIX/share/doc/aegis-oom/README.md"
rmdir "$PREFIX/share/doc/aegis-oom" 2>/dev/null || true
if [ "${1:-}" = "--purge" ]; then
  rm -f /etc/aegis/aegis-oom.conf /etc/aegis/aegis-oom.conf.default /var/lib/aegis/learned
  rmdir /etc/aegis /var/lib/aegis 2>/dev/null || true
  echo "Config and learned baseline removed (--purge)"
else
  echo "/etc/aegis/aegis-oom.conf kept (use --purge to remove it)"
fi
echo "Done."
