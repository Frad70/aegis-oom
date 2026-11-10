#!/usr/bin/env bash
# cases_oom.sh: OOM killer victim-selection matrix, built on the test_harness.sh
# pattern: workers set comm via prctl(PR_SET_NAME); blast radius is bounded by a
# dedicated cgroup ($OOMTEST/<leaf>) with a memory.max backstop; aegis-oom is
# driven with --once and run as the unprivileged user (workers are same-uid).

# worker: prctl-name + allocate+touch <megs> MB, then sleep. comm <=15 chars.
OOM_PYBODY='import ctypes,sys,time
ctypes.CDLL("libc.so.6").prctl(15, sys.argv[1].encode(),0,0,0)
x=bytearray(int(sys.argv[2])*1024*1024)
for i in range(0,len(x),4096): x[i]=1
time.sleep(2000)'

OOM_LAST=0   # pid of the most recently spawned worker

oom_base() {            # create the OOM test root with the memory controller enabled
  # enable memory on the root cgroup first (a no-op where already done,
  # essential on a CI runner where it is not), as test_harness.sh does.
  cgwrite "+memory" "$CGROOT/cgroup.subtree_control"
  priv mkdir -p "$OOMTEST"
  cgwrite "+memory" "$OOMTEST/cgroup.subtree_control"
}
oom_leaf() {            # <leafname> : leaf cgroup with a 1G memory.max backstop
  local cg="$OOMTEST/$1"
  priv mkdir -p "$cg"
  cgwrite "1G" "$cg/memory.max"
}
oom_spawn() {           # <leafname> <comm> <megs> -> OOM_LAST=pid
  local cg="$OOMTEST/$1" comm="$2" megs="$3" pid
  python3 -c "$OOM_PYBODY" "$comm" "$megs" >/dev/null 2>&1 &
  pid=$!
  disown "$pid" 2>/dev/null || true   # silence job-control 'Killed' noise on reap
  cgwrite "$pid" "$cg/cgroup.procs"
  OOM_LAST=$pid
}
oom_run() {             # run aegis-oom --once as the user; stderr -> oom.err
  "$OOM_BIN" --once --no-arm --no-conf --no-learn "$@" --state "$STATE_DIR/oom.state" 2>"$STATE_DIR/oom.err"
}
oom_settle() { sleep 1.5; }   # let workers allocate + set comm

# pick (dry-run) cases
oom_pick_biggest() {            # no protect -> biggest unprotected wins
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a wsmall 90
  oom_spawn a wbig  180
  oom_settle
  out="$(oom_run --dry-run --scope "$OOMTEST/a" --protect __none__)"
  if echo "$out" | grep -q "comm=wbig "; then sub_ok "victim=wbig (largest): $out"
  else sub_bad "victim not wbig: $out"; f=1; fi
  reap_tree "$OOMTEST"; return $f
}

oom_protect_bigger() {          # protect skips a BIGGER protected proc
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a wprot 200          # protected, larger
  oom_spawn a whog  120          # victim, smaller
  oom_settle
  out="$(oom_run --dry-run --scope "$OOMTEST/a" --protect wprot)"
  if echo "$out" | grep -q "comm=whog "; then sub_ok "victim=whog (smaller, unprotected)"
  else sub_bad "victim not whog: $out"; f=1; fi
  if echo "$out" | grep -q "comm=wprot "; then sub_bad "victim is the protected (bigger) proc!"; f=1
  else sub_ok "bigger protected proc skipped"; fi
  reap_tree "$OOMTEST"; return $f
}

oom_protect_multiple() {        # two protected names, victim = only unprotected
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a wp1 150
  oom_spawn a wp2 160
  oom_spawn a whog 120
  oom_settle
  out="$(oom_run --dry-run --scope "$OOMTEST/a" --protect wp1,wp2)"
  if echo "$out" | grep -q "comm=whog "; then sub_ok "victim=whog (only unprotected)"
  else sub_bad "victim not whog: $out"; f=1; fi
  reap_tree "$OOMTEST"; return $f
}

oom_adj_weight() {              # oom_score_adj bias makes a same-size proc the victim
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a wa 120; local a=$OOM_LAST
  oom_spawn a wb 120; local b=$OOM_LAST
  printf '%s' 600 | priv tee "/proc/$b/oom_score_adj" >/dev/null 2>&1
  oom_settle
  out="$(oom_run --dry-run --scope "$OOMTEST/a" --protect __none__)"
  if echo "$out" | grep -q "comm=wb "; then sub_ok "victim=wb (oom_score_adj +600 adds ~600MB to score)"
  else sub_bad "adj-weighting not applied, victim: $out"; f=1; fi
  reap_tree "$OOMTEST"; return $f
}

oom_multi_hog() {               # biggest of several hogs is the single victim
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a h1 80
  oom_spawn a h2 140
  oom_spawn a h3 200
  oom_settle
  out="$(oom_run --dry-run --scope "$OOMTEST/a" --protect __none__)"
  if echo "$out" | grep -q "comm=h3 "; then sub_ok "victim=h3 (largest of three)"
  else sub_bad "victim not h3: $out"; f=1; fi
  reap_tree "$OOMTEST"; return $f
}

oom_all_protected() {           # everything protected -> no victim, nobody dies
  local f=0 out; oom_base; oom_leaf a
  oom_spawn a wp1 150; local p1=$OOM_LAST
  oom_spawn a wp2 120; local p2=$OOM_LAST
  oom_settle
  out="$(oom_run --live --force hard --scope "$OOMTEST/a" --protect wp1,wp2)"
  if echo "$out" | grep -q "victim none"; then sub_ok "no victim selected (all protected)"
  else sub_bad "a victim was selected despite all-protected: $out"; f=1; fi
  sleep 0.4
  kill -0 "$p1" 2>/dev/null && sub_ok "wp1 alive" || { sub_bad "wp1 killed!"; f=1; }
  kill -0 "$p2" 2>/dev/null && sub_ok "wp2 alive" || { sub_bad "wp2 killed!"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

# kill (live) cases
oom_kill_hard() {               # hard -> SIGKILL; victim dies, protected survives
  local f=0; oom_base; oom_leaf a
  oom_spawn a wprot 200; local prot=$OOM_LAST
  oom_spawn a whog  120; local hog=$OOM_LAST
  oom_settle
  oom_run --live --force hard --scope "$OOMTEST/a" --protect wprot >/dev/null
  sleep 0.5
  kill -0 "$hog"  2>/dev/null && { sub_bad "victim whog still alive"; f=1; } || sub_ok "victim whog killed"
  kill -0 "$prot" 2>/dev/null && sub_ok "protected wprot alive" || { sub_bad "protected wprot killed!"; f=1; }
  grep -q SIGKILL "$STATE_DIR/oom.err" && sub_ok "signal was SIGKILL" || { sub_bad "no SIGKILL in log"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

oom_kill_soft() {               # soft -> SIGTERM
  local f=0; oom_base; oom_leaf a
  oom_spawn a wprot 200; local prot=$OOM_LAST
  oom_spawn a whog  120; local hog=$OOM_LAST
  oom_settle
  oom_run --live --force soft --scope "$OOMTEST/a" --protect wprot >/dev/null
  sleep 0.6
  kill -0 "$hog"  2>/dev/null && { sub_bad "victim whog still alive"; f=1; } || sub_ok "victim whog terminated"
  kill -0 "$prot" 2>/dev/null && sub_ok "protected wprot alive" || { sub_bad "protected wprot killed!"; f=1; }
  grep -q SIGTERM "$STATE_DIR/oom.err" && sub_ok "signal was SIGTERM" || { sub_bad "no SIGTERM in log"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

oom_scope_blast() {             # never kills outside the --scope cgroup
  local f=0; oom_base; oom_leaf inside; oom_leaf outside
  oom_spawn inside  whog 120; local hog=$OOM_LAST
  oom_spawn outside wbig 220; local big=$OOM_LAST   # bigger, but out of scope
  oom_settle
  oom_run --live --force hard --scope "$OOMTEST/inside" --protect __none__ >/dev/null
  sleep 0.5
  kill -0 "$hog" 2>/dev/null && { sub_bad "in-scope whog alive"; f=1; } || sub_ok "in-scope whog killed"
  kill -0 "$big" 2>/dev/null && sub_ok "out-of-scope wbig untouched (larger, outside blast radius)" \
                              || { sub_bad "out-of-scope wbig killed, blast radius leaked"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

oom_forced_reason() {          # --force is logged as forced, not as a threshold trigger
  local f=0; oom_base; oom_leaf a
  oom_spawn a wforce 120
  oom_settle
  oom_run --live --force hard --scope "$OOMTEST/a" --protect __none__ >/dev/null
  sleep 0.4
  if grep -q "KILL:.* forced " "$STATE_DIR/oom.err"; then sub_ok "forced kill is logged with reason forced"
  else sub_bad "reason is not forced: $(grep -o 'KILL:.*' "$STATE_DIR/oom.err" | head -1)"; f=1; fi
  if grep -qE "KILL:.* (avail|psi\+scarce) " "$STATE_DIR/oom.err"; then
    sub_bad "forced kill poses as a threshold trigger"; f=1
  else sub_ok "forced kill does not pose as a threshold trigger"; fi
  reap_tree "$OOMTEST"; return $f
}

oom_dryrun_nokill() {           # dry-run kills nothing
  local f=0; oom_base; oom_leaf a
  oom_spawn a w1 120; local p1=$OOM_LAST
  oom_spawn a w2 150; local p2=$OOM_LAST
  oom_settle
  oom_run --dry-run --force hard --scope "$OOMTEST/a" --protect __none__ >/dev/null
  sleep 0.4
  kill -0 "$p1" 2>/dev/null && sub_ok "w1 alive" || { sub_bad "w1 killed in dry-run!"; f=1; }
  kill -0 "$p2" 2>/dev/null && sub_ok "w2 alive" || { sub_bad "w2 killed in dry-run!"; f=1; }
  grep -q 'DRYRUN would kill' "$STATE_DIR/oom.err" && sub_ok "logged 'DRYRUN would kill'" \
    || sub_bad "no DRYRUN log line"
  reap_tree "$OOMTEST"; return $f
}

# cgroup.kill: a batch leaf dies whole, not one random process
oom_run_priv() {        # same as oom_run but privileged: writing cgroup.kill needs root
  priv env AEG_OOM_CGROUP_KILL=1 "$OOM_BIN" --once --no-arm --no-conf --no-learn "$@" --state "$STATE_DIR/oom.state" 2>"$STATE_DIR/oom.err"
}

oom_cgroup_kill_leaf() {        # whole leaf scope dies, not just the fattest member
  local f=0; oom_base; oom_leaf "batch.scope"
  oom_spawn "batch.scope" wjob1 150; local p1=$OOM_LAST
  oom_spawn "batch.scope" wjob2 120; local p2=$OOM_LAST
  oom_settle
  oom_run_priv --live --force hard --scope "$OOMTEST/batch.scope" --protect __none__ >/dev/null
  sleep 0.6
  grep -q 'via=cgroup.kill' "$STATE_DIR/oom.err" && sub_ok "used cgroup.kill" \
    || { sub_bad "did not use cgroup.kill: $(tail -1 "$STATE_DIR/oom.err")"; f=1; }
  kill -0 "$p1" 2>/dev/null && { sub_bad "wjob1 alive"; f=1; } || sub_ok "wjob1 killed"
  kill -0 "$p2" 2>/dev/null && { sub_bad "wjob2 alive, leaf not killed whole"; f=1; } || sub_ok "wjob2 killed too"
  reap_tree "$OOMTEST"; return $f
}

oom_cgroup_kill_guard() {       # protected neighbour in the leaf -> fall back to a signal
  local f=0; oom_base; oom_leaf "mixed.scope"
  oom_spawn "mixed.scope" whog  150; local hog=$OOM_LAST
  oom_spawn "mixed.scope" wprot 120; local prot=$OOM_LAST
  oom_settle
  oom_run_priv --live --force hard --scope "$OOMTEST/mixed.scope" --protect wprot >/dev/null
  sleep 0.6
  grep -q 'via=pidfd' "$STATE_DIR/oom.err" && sub_ok "fell back to pidfd (protected neighbour)" \
    || { sub_bad "expected pidfd fallback: $(tail -1 "$STATE_DIR/oom.err")"; f=1; }
  kill -0 "$hog" 2>/dev/null && { sub_bad "whog alive"; f=1; } || sub_ok "whog killed"
  kill -0 "$prot" 2>/dev/null && sub_ok "wprot survived" || { sub_bad "wprot killed, guard failed"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

oom_cgroup_kill_off() {         # knob off -> classic single-process signal
  local f=0; oom_base; oom_leaf "off.scope"
  oom_spawn "off.scope" wone 150; local p1=$OOM_LAST
  oom_spawn "off.scope" wtwo 120; local p2=$OOM_LAST
  oom_settle
  oom_run --live --force hard --scope "$OOMTEST/off.scope" --protect __none__ >/dev/null
  sleep 0.6
  kill -0 "$p1" 2>/dev/null && { sub_bad "wone alive"; f=1; } || sub_ok "wone killed"
  kill -0 "$p2" 2>/dev/null && sub_ok "wtwo untouched (knob off => single process)" \
    || { sub_bad "wtwo killed with AEG_OOM_CGROUP_KILL unset"; f=1; }
  reap_tree "$OOMTEST"; return $f
}

# the standalone integration harness
oom_harness() {
  [ -x "$TESTS_DIR/test_harness.sh" ] || { note "skip: test_harness.sh absent"; return 2; }
  local out rc
  priv mkdir -p "$OOMTEST"
  out="$(priv env AEG_TEST_CGROUP="$OOMTEST/harness.scope" bash "$TESTS_DIR/test_harness.sh" 2>&1)"; rc=$?
  case "$rc" in
    0) sub_ok "test_harness.sh: $(printf '%s\n' "$out" | tail -1)"; return 0 ;;
    2) note "skip: harness prerequisites unmet"; return 2 ;;
    *) sub_bad "test_harness.sh failed (rc=$rc)"; printf '%s\n' "$out" | tail -5; return 1 ;;
  esac
}

register_oom() {
  add_case full oom "oom:pick-biggest"      "victim = biggest unprotected proc"          'oom_pick_biggest'
  add_case full oom "oom:protect-bigger"    "protect-list skips a BIGGER protected proc" 'oom_protect_bigger'
  add_case full oom "oom:protect-multiple"  "multiple protected names, victim unprotected" 'oom_protect_multiple'
  add_case full oom "oom:adj-weight"        "oom_score_adj bias steers victim selection" 'oom_adj_weight'
  add_case full oom "oom:multi-hog"         "biggest of several hogs is the single victim" 'oom_multi_hog'
  add_case full oom "oom:all-protected"     "all protected -> no victim, nobody dies"     'oom_all_protected'
  add_case full oom "oom:kill-hard"         "hard force -> SIGKILL victim, protected survives" 'oom_kill_hard'
  add_case full oom "oom:kill-soft"         "soft force -> SIGTERM victim, protected survives" 'oom_kill_soft'
  add_case full oom "oom:scope-blast"       "never kills outside --scope (blast radius)"  'oom_scope_blast'
  add_case full oom "oom:dryrun-nokill"     "dry-run kills nothing"                       'oom_dryrun_nokill'
  add_case full oom "oom:forced-reason"     "--force logs reason=forced, not a threshold"  'oom_forced_reason'
  add_case full oom "oom:cgroup-kill-leaf"  "cgroup.kill takes the whole batch leaf"      'oom_cgroup_kill_leaf'
  add_case full oom "oom:cgroup-kill-guard" "protected neighbour -> fall back to signal"  'oom_cgroup_kill_guard'
  add_case full oom "oom:cgroup-kill-off"   "knob off -> single-process signal"           'oom_cgroup_kill_off'
  add_case full oom "oom:harness"           "existing test_harness.sh integration test"   'oom_harness'
}

# fast-tier smokes (light)
register_oom_smoke() {
  add_case fast smoke "smoke:oom-dryrun-pick" "dry-run victim pick (smaller unprotected)" 'oom_pick_biggest'
  add_case fast smoke "smoke:oom-hard-kill"   "live hard kill (victim dies, protected lives)" 'oom_kill_hard'
}
