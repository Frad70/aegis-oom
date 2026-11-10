#!/usr/bin/env bash
# test_harness.sh: integration test of aegis-oom in an isolated cgroup.
# Requires root. Really checks the protect list: the protected process is made the
# LARGEST, and the killer must skip it and pick the SMALLER hog. comm is set through
# prctl(PR_SET_NAME): exec -a changes only argv[0], and the killer reads /proc/pid/comm.
# The blast radius is limited to the test cgroup through --scope.
set -u
BIN="$(dirname "$0")/../aegis-oom"
CG=${AEG_TEST_CGROUP:-/sys/fs/cgroup/aegis-oomtest-$(date +%s%N)-$BASHPID}
PROT_NAME="bigprot"      # protected, the largest (~200 MB)
HOG_NAME="memhog"        # victim, smaller (~120 MB)
FAIL=0
note(){ printf '  %s\n' "$*"; }
ok(){ printf 'PASS: %s\n' "$*"; }
bad(){ printf 'FAIL: %s\n' "$*"; FAIL=1; }

[ "$(id -u)" -eq 0 ] || { echo "root is required (sudo)"; exit 2; }
[ -x "$BIN" ] || { echo "binary $BIN not found; build it: make aegis-oom"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }
HSTATE_DIR=$(mktemp -d /tmp/aegis-harness.XXXXXX)
HSTATE="$HSTATE_DIR/oom.state"

cleanup(){
  [ -f "$CG/cgroup.procs" ] && \
    while read -r p; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done < "$CG/cgroup.procs"
  sleep 0.3; rmdir "$CG" 2>/dev/null
  rm -rf "$HSTATE_DIR"
}
trap cleanup EXIT

# worker body: sets comm through prctl, allocates megs MB, sleeps. argv: name megs
PYBODY='
import ctypes, sys, time
name = sys.argv[1].encode()
megs = int(sys.argv[2])
ctypes.CDLL("libc.so.6", use_errno=True).prctl(15, name, 0, 0, 0)  # PR_SET_NAME
x = bytearray(megs * 1024 * 1024)
for i in range(0, len(x), 4096): x[i] = 1
time.sleep(600)
'
spawn(){ python3 -c "$PYBODY" "$1" "$2" >/dev/null 2>&1 & echo $!; }

rmdir "$CG" 2>/dev/null
mkdir -p "$CG"
echo +memory > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
echo 1G > "$CG/memory.max" 2>/dev/null || true   # room for both, so the kernel OOM does NOT fire

prot=$(spawn "$PROT_NAME" 200)
hog=$(spawn "$HOG_NAME" 120)
echo "$prot" > "$CG/cgroup.procs"
echo "$hog"  > "$CG/cgroup.procs"
sleep 2   # let them allocate and set comm

note "cgroup $CG: protect=$prot($PROT_NAME ~200M) hog=$hog($HOG_NAME ~120M)"
note "comm: protect=$(cat /proc/$prot/comm 2>/dev/null) hog=$(cat /proc/$hog/comm 2>/dev/null)"
[ "$(cat /proc/$prot/comm 2>/dev/null)" = "$PROT_NAME" ] || bad "sanity: comm of the protected process != $PROT_NAME (the test is meaningless)"

# Test 1: victim choice (dry-run, scope). The protected one is LARGER: without protect it would be picked
OUT=$("$BIN" --once --dry-run --no-arm --no-conf --no-learn --scope "$CG" --protect "$PROT_NAME" \
        --state "$HSTATE" 2>/dev/null)
note "choice: $OUT"
if echo "$OUT" | grep -q "comm=$HOG_NAME"; then ok "T1 victim = $HOG_NAME (smaller)"; else bad "T1 victim is not $HOG_NAME: $OUT"; fi
if echo "$OUT" | grep -q "comm=$PROT_NAME"; then bad "T1 picked the protected process (although larger)!"; else ok "T1 protected (larger) process skipped"; fi

# Test 2: real kill (force hard, scope)
"$BIN" --once --live --no-arm --no-conf --no-learn --force hard --scope "$CG" --protect "$PROT_NAME" \
       --state "$HSTATE" >/dev/null 2>&1
sleep 0.5
if kill -0 "$hog" 2>/dev/null; then bad "T2 hog $hog is alive (not killed)"; else ok "T2 hog killed"; fi
if kill -0 "$prot" 2>/dev/null; then ok "T2 protected $prot is alive"; else bad "T2 protected process killed!"; fi

rm -f "$HSTATE"
[ "$FAIL" -eq 0 ] && echo "HARNESS: all passed" || echo "HARNESS: failures"
exit "$FAIL"
