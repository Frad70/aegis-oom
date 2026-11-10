#!/usr/bin/env bash
# tests/run.sh: tiered root integration tests for aegis-reaper and aegis-oom.
#
#   ./tests/run.sh --tier fast            # two smoke cases
#   ./tests/run.sh --tier full            # fast plus the full matrix
#   ./tests/run.sh --list                 # list all cases with their tier + counts
#   ./tests/run.sh --only id1,id2,...     # run exactly these case ids (any tier)
#
# SAFETY: fork-bomb / reaper cases use a dedicated test cgroup root
# (/sys/fs/cgroup/aegis-citest-<run-id>) and a dedicated test reaper instance pointed at
# it; the live system reaper (which watches user.slice) is never touched.
# Privileged cgroup operations use sudo when not run as root. Without root,
# passwordless sudo or cgroup v2 the run prints SKIP and exits 0.
#
# Exit code: nonzero if any selected case fails. Skips do not fail.
set -uo pipefail
ORIGINAL_ARGS=("$@")

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export STATE_DIR="$(mktemp -d /tmp/aegis-tests.XXXXXX)"

# shellcheck source=tests/lib.sh
. "$HERE/lib.sh"
. "$HERE/cases_forkbomb.sh"
. "$HERE/cases_oom.sh"

# case registry
declare -a T_TIER T_CAT T_ID T_DESC T_RUN
add_case() { T_TIER+=("$1"); T_CAT+=("$2"); T_ID+=("$3"); T_DESC+=("$4"); T_RUN+=("$5"); }

register_forkbomb_smoke
register_oom_smoke
register_forkbomb
register_oom

NCASES=${#T_ID[@]}

# arg parsing
TIER=fast; DO_LIST=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) TIER="${2:-fast}"; shift 2 ;;
    --tier=*) TIER="${1#*=}"; shift ;;
    --list) DO_LIST=1; shift ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$TIER" in fast|full) ;; *) echo "tier must be fast|full" >&2; exit 2 ;; esac

# counts
count_fast=0; count_full=0
for t in "${T_TIER[@]}"; do
  [ "$t" = fast ] && count_fast=$((count_fast+1))
  [ "$t" = full ] && count_full=$((count_full+1))
done
count_total=$((count_fast+count_full))

# list
if [ "$DO_LIST" = 1 ]; then
  printf '%-4s %-6s %-10s %-26s %s\n' "#" "TIER" "CAT" "ID" "DESCRIPTION"
  printf '%s\n' "-------------------------------------------------------------------------------"
  for i in $(seq 0 $((NCASES-1))); do
    printf '%-4s %-6s %-10s %-26s %s\n' "$((i+1))" "${T_TIER[$i]}" "${T_CAT[$i]}" "${T_ID[$i]}" "${T_DESC[$i]}"
  done
  printf '%s\n' "-------------------------------------------------------------------------------"
  printf 'fast tier:  %d cases\n' "$count_fast"
  printf 'full-only:  %d cases\n' "$count_full"
  printf 'full tier:  %d cases (fast + full-only)\n' "$count_total"
  if [ "$count_total" -ge 30 ] && [ "$count_total" -le 70 ]; then
    printf 'full-tier count %d is within the target band [30, 70]. OK\n' "$count_total"
  else
    printf 'WARNING: full-tier count %d is OUTSIDE the target band [30, 70]\n' "$count_total"
  fi
  rm -rf "$STATE_DIR"
  exit 0
fi

# selection
declare -a SEL
if [ -n "$ONLY" ]; then
  IFS=',' read -r -a want <<< "$ONLY"
  for i in $(seq 0 $((NCASES-1))); do
    for w in "${want[@]}"; do [ "${T_ID[$i]}" = "$w" ] && SEL+=("$i"); done
  done
  [ "${#SEL[@]}" -gt 0 ] || { echo "no case ids matched: $ONLY" >&2; rm -rf "$STATE_DIR"; exit 2; }
else
  for i in $(seq 0 $((NCASES-1))); do
    if [ "$TIER" = full ]; then SEL+=("$i")
    elif [ "${T_TIER[$i]}" = fast ]; then SEL+=("$i"); fi
  done
fi

# runtime guards and cleanup: every case here needs cgroup v2 and privileges
if [ "$(stat -fc %T "$CGROOT" 2>/dev/null)" != cgroup2fs ]; then
  echo "SKIP: root integration tests (no cgroup v2 at $CGROOT)"; rm -rf "$STATE_DIR"; exit 0
fi
if [ "$PRIV_NEED" = 1 ] && ! sudo -n true 2>/dev/null; then
  echo "SKIP: root integration tests (need root or passwordless sudo)"; rm -rf "$STATE_DIR"; exit 0
fi
trap 'rc=$?; reap_all_quiet; rm -rf "$STATE_DIR"; exit $rc' EXIT
reap_all_quiet
prepare_binaries || { echo "core build failed" >&2; exit 1; }

# run
PASS=0; FAIL=0; SKIP=0
declare -a FAILED
printf '\n=== aegis tests: tier=%s  selected=%d/%d ===\n' "$TIER" "${#SEL[@]}" "$NCASES"

n=0
for i in "${SEL[@]}"; do
  n=$((n+1))
  printf '\n[%d/%d] %s  (%s/%s)\n      %s\n' \
    "$n" "${#SEL[@]}" "${T_ID[$i]}" "${T_TIER[$i]}" "${T_CAT[$i]}" "${T_DESC[$i]}"
  rc=0
  eval "${T_RUN[$i]}" || rc=$?
  reap_all_quiet
  case "$rc" in
    0) PASS=$((PASS+1)); printf '   => PASS  %s\n' "${T_ID[$i]}" ;;
    2) SKIP=$((SKIP+1)); printf '   => SKIP  %s\n' "${T_ID[$i]}" ;;
    *) FAIL=$((FAIL+1)); FAILED+=("${T_ID[$i]}"); printf '   => FAIL  %s\n' "${T_ID[$i]}" ;;
  esac
done

# summary
printf '\n==================== SUMMARY ====================\n'
printf 'tier=%s  selected=%d  PASS=%d  FAIL=%d  SKIP=%d\n' "$TIER" "${#SEL[@]}" "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then printf 'FAILED: %s\n' "${FAILED[*]}"; fi
printf '================================================\n'

[ "$FAIL" -eq 0 ]
