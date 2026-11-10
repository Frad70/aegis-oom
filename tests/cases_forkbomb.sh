#!/usr/bin/env bash
# cases_forkbomb.sh: fork bomb and reaper integration matrix.
#
# Every case runs inside the dedicated test root $CITEST with a DEDICATED test
# reaper instance pointed at $CITEST. Each bomb leaf gets a pids.max backstop and
# a per-case watchdog; teardown cgroup.kill's + rmdir's the whole subtree.

FB_PIDSMAX=4000          # per-leaf backstop: a runaway can never exceed this

# leaf spawn
fb_leaf_spawn() {        # <leafname> <shape> <target>
  local leaf="$CITEST/$1"
  priv mkdir -p "$leaf"
  cgwrite "$FB_PIDSMAX" "$leaf/pids.max"
  priv bash "$TESTS_DIR/spawn_leaf.sh" "$leaf" "$2" "$3" >>"$STATE_DIR/spawn.log" 2>&1 &
  disown 2>/dev/null || true
}

# deep-nested child cgroups: procs live in leaf/d1/d2/d3 (tests reaper's recursive
# deepest-leaf scan).
fb_nest_spawn() {        # <leafname> <target>
  local base="$CITEST/$1"
  priv mkdir -p "$base/d1/d2/d3"
  cgwrite "+pids" "$base/cgroup.subtree_control"
  cgwrite "+pids" "$base/d1/cgroup.subtree_control"
  cgwrite "+pids" "$base/d1/d2/cgroup.subtree_control"
  cgwrite "$FB_PIDSMAX" "$base/d1/d2/d3/pids.max"
  priv bash "$TESTS_DIR/spawn_leaf.sh" "$base/d1/d2/d3" flood "$2" >>"$STATE_DIR/spawn.log" 2>&1 &
  disown 2>/dev/null || true
}

# observation helpers
fb_total()      { cat "$CITEST/pids.current" 2>/dev/null || echo 0; }
fb_leaf_pids()  { cat "$CITEST/$1/pids.current" 2>/dev/null || echo 0; }   # counts descendants too
fb_wait_total_ge()    { local n="$1" t="$2" i; for ((i=0;i<t*5;i++)); do [ "$(fb_total)" -ge "$n" ] && return 0; sleep 0.2; done; return 1; }
fb_wait_total_lt()    { local n="$1" t="$2" i; for ((i=0;i<t*5;i++)); do [ "$(fb_total)" -lt "$n" ] && return 0; sleep 0.2; done; return 1; }
fb_wait_leaf_ge()     { local l="$1" n="$2" t="$3" i; for ((i=0;i<t*5;i++)); do [ "$(fb_leaf_pids "$l")" -ge "$n" ] && return 0; sleep 0.2; done; return 1; }

# case: reaper kills the bomb leaf/leaves, system returns to baseline
fb_killall() {           # <shape> <nleaves> <target> <threshold> <leaf_min>
  local shape="$1" n="$2" target="$3" thr="$4" lmin="$5" f=0 k wd
  cg_ensure_citest
  wd="$(watchdog_arm 25)"
  for ((k=1; k<=n; k++)); do
    if [ "$shape" = nested ]; then fb_nest_spawn "leaf$k" "$target"
    else fb_leaf_spawn "leaf$k" "$shape" "$target"; fi
  done
  fb_wait_total_ge "$thr" 8 || note "warn: total only reached $(fb_total) before threshold $thr"
  reaper_start "$thr" "$lmin"
  if fb_wait_total_lt "$lmin" 15; then sub_ok "drained to baseline (<$lmin), total=$(fb_total)"
  else sub_bad "NOT drained: total=$(fb_total) (threshold=$thr leaf_min=$lmin)"; f=1; fi
  reaper_stop
  if grep -q 'reaper: killed fork bomb' "$REAPER_LOG"; then sub_ok "reaper killed leaf(s) via cgroup.kill"
  else sub_bad "reaper logged no kill"; f=1; fi
  if grep -q 'no single leaf to kill' "$REAPER_LOG"; then sub_bad "reaper logged 'no leaf'"; f=1
  else sub_ok "no 'no leaf' message"; fi
  watchdog_disarm "$wd"
  reap_tree "$CITEST"
  return $f
}

# case: below threshold -> reaper must NOT trigger
fb_below_threshold() {   # <shape> <target>
  local shape="$1" target="$2" f=0 wd cur
  cg_ensure_citest
  wd="$(watchdog_arm 20)"
  fb_leaf_spawn leaf1 "$shape" "$target"
  fb_wait_total_ge "$target" 8 || note "warn: leaf ramped only to $(fb_total)"
  reaper_start 50000 50          # threshold far above the workload
  sleep 3
  reaper_stop
  cur="$(fb_total)"
  if [ "$cur" -ge "$((target/2))" ]; then sub_ok "leaf survived (total=$cur, threshold never reached)"
  else sub_bad "leaf vanished unexpectedly (total=$cur)"; f=1; fi
  if grep -q 'reaper: killed fork bomb' "$REAPER_LOG"; then sub_bad "reaper acted below threshold!"; f=1
  else sub_ok "reaper took no action"; fi
  watchdog_disarm "$wd"
  reap_tree "$CITEST"
  return $f
}

# case: threshold crossed but worst leaf < leaf_min -> refuse, log 'no leaf'
fb_below_leafmin() {     # <shape> <target> <threshold> <leaf_min>
  local shape="$1" target="$2" thr="$3" lmin="$4" f=0 wd cur
  cg_ensure_citest
  wd="$(watchdog_arm 20)"
  fb_leaf_spawn leaf1 "$shape" "$target"
  fb_wait_total_ge "$thr" 8 || note "warn: total only reached $(fb_total) before threshold $thr"
  reaper_start "$thr" "$lmin"
  sleep 3
  reaper_stop
  cur="$(fb_total)"
  if [ "$cur" -ge "$((target/2))" ]; then sub_ok "leaf survived (total=$cur; worst leaf < leaf_min=$lmin)"
  else sub_bad "leaf killed despite being < leaf_min (total=$cur)"; f=1; fi
  if grep -q 'no single leaf to kill' "$REAPER_LOG"; then sub_ok "reaper triggered but refused (< leaf_min)"
  else sub_bad "expected 'no leaf' message absent"; f=1; fi
  if grep -q 'reaper: killed fork bomb' "$REAPER_LOG"; then sub_bad "reaper killed a sub-leaf_min leaf!"; f=1
  else sub_ok "no kill issued"; fi
  watchdog_disarm "$wd"
  reap_tree "$CITEST"
  return $f
}

# case: worst-leaf precision (big dies, smaller one is preserved)
fb_worst_pick() {
  local f=0 wd b s
  cg_ensure_citest
  wd="$(watchdog_arm 20)"
  # spawn both leaves to full BEFORE starting the reaper (removes the timing race)
  fb_leaf_spawn big   flood 600
  fb_leaf_spawn small flood 300
  fb_wait_leaf_ge big   550 10 || note "warn: big ramped to $(fb_leaf_pids big)"
  fb_wait_leaf_ge small 280 10 || note "warn: small ramped to $(fb_leaf_pids small)"
  # total ~900; threshold 800 -> kill worst (big ~600) -> total ~300 < 800 -> stop
  reaper_start 800 100
  sleep 3
  reaper_stop
  b="$(fb_leaf_pids big)"; s="$(fb_leaf_pids small)"
  if [ "$b" -lt 100 ]; then sub_ok "worst leaf 'big' killed (big=$b)"; else sub_bad "big leaf survived (big=$b)"; f=1; fi
  if [ "$s" -ge 200 ]; then sub_ok "smaller leaf 'small' preserved (small=$s)"; else sub_bad "smaller leaf wrongly drained (small=$s)"; f=1; fi
  if grep -q "$CITEST/big" "$REAPER_LOG"; then sub_ok "reaper named 'big' as victim"
  else note "reaper kill line: $(grep 'reaper: killed fork bomb' "$REAPER_LOG" | head -1)"; fi
  watchdog_disarm "$wd"
  reap_tree "$CITEST"
  return $f
}

register_forkbomb() {
  local shape n
  # shapes x simultaneous-leaf counts: reaper drains each to baseline
  for shape in classic recursion exec nested; do
    for n in 1 3 5; do
      add_case full forkbomb "forkbomb:$shape:n$n" \
        "$shape bomb x$n leaf(s) -> reaper drains to baseline" \
        "fb_killall $shape $n 180 130 70"
    done
  done
  # negative + precision cases
  add_case full forkbomb "forkbomb:below-threshold" \
    "load under threshold -> reaper must NOT trigger" \
    "fb_below_threshold flood 200"
  add_case full forkbomb "forkbomb:below-leaf_min" \
    "threshold crossed but worst leaf < leaf_min -> 'no leaf', no kill" \
    "fb_below_leafmin flood 200 120 400"
  add_case full forkbomb "forkbomb:worst-leaf-pick" \
    "two leaves -> reaper kills the bigger, preserves the smaller" \
    "fb_worst_pick"
}

# fast-tier smoke (light single leaf)
register_forkbomb_smoke() {
  add_case fast smoke "smoke:reaper-kills-leaf" \
    "tiny single-leaf bomb -> test reaper kills it" \
    "fb_killall flood 1 150 100 50"
}
