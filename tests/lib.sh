#!/usr/bin/env bash
# tests/lib.sh: shared infrastructure for the aegis test framework.
#
# SAFETY MODEL (see README.md, Tests):
#   * Every fork-bomb / reaper test runs inside a DEDICATED test cgroup root
#     $CITEST under /sys/fs/cgroup, never /sys/fs/cgroup/user.slice.
#   * The reaper under test is a DEDICATED TEST INSTANCE pointed at $CITEST, so it
#     can never be confused with (or kill on behalf of) the live system reaper,
#     which watches user.slice. Teardown kills only the PID this run started.
#   * Every bomb leaf gets a pids.max backstop; every cgroup write goes through one
#     helper (sudo-redirect-safe); teardown cgroup.kill's the whole subtree and
#     rmdir's it, on success AND on failure.
#
# This file only provides infrastructure. Case definitions live in
# cases_forkbomb.sh / cases_oom.sh.

# paths (derived from this script's location; no hardcoded repo path)
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$LIB_DIR"
REPO="$(cd "$TESTS_DIR/.." && pwd)"

CGROOT=/sys/fs/cgroup
TEST_RUN_ID="$(date +%s%N)-$BASHPID"
CITEST="$CGROOT/aegis-citest-$TEST_RUN_ID"          # dedicated reaper/fork-bomb test root
OOMTEST="$CGROOT/aegis-oomtest-ci-$TEST_RUN_ID"     # dedicated OOM-killer test root

REAPER_BIN="$REPO/aegis-reaper"
OOM_BIN="$REPO/aegis-oom"

STATE_DIR="${STATE_DIR:-$(mktemp -d /tmp/aegis-tests.XXXXXX)}"
REAPER_LOG="$STATE_DIR/reaper.log"

# privilege: run directly if root, else passwordless sudo
if [ "$(id -u)" = 0 ]; then PRIV_NEED=0; else PRIV_NEED=1; fi
priv() { if [ "$PRIV_NEED" = 1 ]; then sudo "$@"; else "$@"; fi; }

# cgroup write that survives the `sudo echo > file` footgun (redirect happens in
# the UNPRIVILEGED shell otherwise). Always pipe through a privileged tee.
cgwrite() { printf '%s' "$1" | priv tee "$2" >/dev/null 2>&1; }

# logging / sub-assertions
note()    { printf '      . %s\n' "$*"; }
sub_ok()  { printf '      [ok]   %s\n' "$*"; }
sub_bad() { printf '      [BAD]  %s\n' "$*"; }

# cgroup teardown (recursive, idempotent, failure-proof)
# cgroup.kill is recursive in cgroup v2: one write tears down the whole subtree.
reap_tree() {
  local root="$1"
  [ -d "$root" ] || return 0
  cgwrite 1 "$root/cgroup.kill" 2>/dev/null
  sleep 0.3
  priv find "$root" -depth -type d -exec rmdir {} + 2>/dev/null
  if [ -d "$root" ]; then sleep 0.3; priv rmdir "$root" 2>/dev/null; fi
}

REAPER_PID=""
reaper_stop() {
  # only the instance this run started; under sudo the signal is relayed to it
  [ -n "$REAPER_PID" ] || return 0
  priv kill "$REAPER_PID" 2>/dev/null
  wait "$REAPER_PID" 2>/dev/null
  REAPER_PID=""
}

# belt-and-suspenders cleanup run between every case and on EXIT
reap_all_quiet() {
  reaper_stop
  reap_tree "$CITEST"
  reap_tree "$OOMTEST"
  # The standalone harness is passed a child of this run's OOMTEST.
}

# watchdog: hard backstop so a bomb can never outlive a case
watchdog_arm() {   # <seconds> -> prints watchdog pid
  ( sleep "$1"
    cgwrite 1 "$CITEST/cgroup.kill" 2>/dev/null
    cgwrite 1 "$OOMTEST/cgroup.kill" 2>/dev/null
  ) </dev/null >/dev/null 2>&1 &
  local wd=$!
  disown "$wd" 2>/dev/null || true
  echo "$wd"
}
watchdog_disarm() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }

# reaper-test cgroup root + reaper instance
cg_ensure_citest() {
  # enable pids on the root cgroup (a no-op where already done, as on a
  # systemd host; essential on a CI runner where it is not, otherwise the
  # leaf pids.current never accounts and the reaper would silently never trigger).
  cgwrite "+pids" "$CGROOT/cgroup.subtree_control"
  [ -d "$CITEST" ] || priv mkdir -p "$CITEST"
  cgwrite "+pids" "$CITEST/cgroup.subtree_control"
}

reaper_start() {   # <pids_threshold> <leaf_min>  (cgroup root is always $CITEST)
  : > "$REAPER_LOG"
  priv "$REAPER_BIN" "$1" "$CITEST" "$2" >"$REAPER_LOG" 2>&1 &
  REAPER_PID=$!
  sleep 0.4   # let it arm + complete first scan
}

# build helpers (used by build cases and by prepare_binaries)
build_reaper_quiet() { ( cd "$REPO" && rm -f aegis-reaper && make -s aegis-reaper ) >/dev/null 2>&1; }
build_oom_quiet()    { ( cd "$REPO" && rm -f aegis-oom && make aegis-oom ) >/dev/null 2>&1; }

# Source-only checkouts contain no ELF files. Let make also check
# source/header dependencies rather than trusting an existing executable.
prepare_binaries() {
  ( cd "$REPO" && make -s all ) || return 1
}
