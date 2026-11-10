#!/usr/bin/env bash
# spawn_leaf.sh <cgroup_abs_path> <shape> <target>
#
# Joins the given cgroup, CONFIRMS placement, then spawns <target> cheap, sleeping
# processes using the requested shape. Runs privileged (writes cgroup.procs).
#
# SAFETY: before forking anything it verifies it is actually inside the target
# cgroup (reading /proc/self/cgroup). If the join failed for any reason it aborts
# without forking, so a flood can therefore never land in the caller's own (live)
# cgroup under user.slice.
#
# The processes only sleep (near-zero CPU/RAM). The "classic" shape is a BOUNDED,
# non-CPU-saturating variant of `:(){ :|:& };:` (self-piping, backgrounded pairs),
# capped at <target> so it cannot run away on a live desktop. The leaf's pids.max
# backstop (set by the caller) bounds it regardless.
set -u

CG="$1"; SHAPE="$2"; N="$3"
SLEEP=4000

echo $$ > "$CG/cgroup.procs" 2>/dev/null || { echo "spawn_leaf: cannot join $CG" >&2; exit 3; }

want="${CG#/sys/fs/cgroup}"
have="$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)"
if [ "$have" != "$want" ]; then
  echo "spawn_leaf: placement mismatch have=$have want=$want, aborting (no fork)" >&2
  exit 4
fi

case "$SHAPE" in
  flood)
    for ((i=0; i<N; i++)); do sleep "$SLEEP" & done
    ;;
  exec)
    # each child re-execs into a fresh process image
    for ((i=0; i<N; i++)); do ( exec sleep "$SLEEP" ) & done
    ;;
  classic)
    # bounded `:|:&`: self-piping, backgrounded pairs (2 procs each)
    c=$(( N / 2 )); [ "$c" -lt 1 ] && c=1
    for ((i=0; i<c; i++)); do { sleep "$SLEEP" | sleep "$SLEEP"; } & done
    ;;
  recursion)
    # function-recursion bomb, depth-bounded to N
    rec() { [ "$1" -le 0 ] && return; sleep "$SLEEP" & rec $(( $1 - 1 )); }
    rec "$N"
    ;;
  *)
    echo "spawn_leaf: unknown shape $SHAPE" >&2; exit 5
    ;;
esac

# Stay alive (and in the cgroup) so the leaf does not empty until reaped; being a
# member, we are killed by the same cgroup.kill that drains the children.
exec sleep "$SLEEP"
