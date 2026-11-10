#include "oom_policy.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); g_fail++; } \
} while (0)

static thresholds base_th(void) {
    thresholds t = {0};
    t.psi_soft = 20.0; t.psi_hard = 40.0;
    t.avail_soft_kb = 800*1024; t.avail_hard_kb = 300*1024;
    t.avail_soft_pct = 0; t.avail_hard_pct = 0;
    t.baseline_k = 2.0; t.sustain_n = 3; t.protect_smart = 1;
    return t;
}

static void test_parse_protect(void) {
    protect_list pl;
    int n = oom_parse_protect("game,daemon,node", &pl);
    CHECK(n == 3, "parse_protect: 3 names");
    CHECK(strcmp(pl.names[0], "game") == 0, "parse_protect: [0]=game");
    CHECK(strcmp(pl.names[2], "node") == 0, "parse_protect: [2]=node");
    n = oom_parse_protect("", &pl);
    CHECK(n == 0, "parse_protect: empty string -> 0");
    n = oom_parse_protect(" a , b ", &pl);
    CHECK(n == 2 && strcmp(pl.names[0],"a")==0 && strcmp(pl.names[1],"b")==0,
          "parse_protect: spaces are trimmed");
}

static void test_is_protected(void) {
    protect_list pl;
    oom_parse_protect("game,daemon,node", &pl);
    CHECK(oom_is_protected("game", &pl) == 1, "is_protected: game is protected");
    CHECK(oom_is_protected("java", &pl) == 0, "is_protected: java is not protected");
    CHECK(oom_is_protected("gam", &pl) == 0, "is_protected: a partial match is not protection");
}

static void test_victim_score(void) {
    protect_list pl; oom_parse_protect("game", &pl);
    thresholds t = base_th();
    proc_sample big   = {.pid=100,.rss_kb=2000000,.swap_kb=0,     .oom_score_adj=0,    .state='R',.comm="browser"};
    proc_sample small = {.pid=101,.rss_kb=100000, .swap_kb=0,     .oom_score_adj=0,    .state='S',.comm="bash"};
    proc_sample swap  = {.pid=102,.rss_kb=100000, .swap_kb=900000,.oom_score_adj=0,    .state='S',.comm="java"};
    proc_sample prot  = {.pid=103,.rss_kb=9000000,.swap_kb=0,     .oom_score_adj=0,    .state='S',.comm="game"};
    proc_sample immune= {.pid=104,.rss_kb=9000000,.swap_kb=0,     .oom_score_adj=-1000,.state='S',.comm="daemon"};
    proc_sample empty = {.pid=105,.rss_kb=0,      .swap_kb=0,     .oom_score_adj=0,    .state='S',.comm="kthread"};
    proc_sample init  = {.pid=1,  .rss_kb=5000,   .swap_kb=0,     .oom_score_adj=0,    .state='S',.comm="systemd"};
    proc_sample self  = {.pid=106,.rss_kb=9000000,.swap_kb=0,     .oom_score_adj=0,    .state='S',.comm="aegis-oom",.flags=PF_SELF};

    CHECK(oom_victim_score(&big,&pl,&t) > oom_victim_score(&small,&pl,&t), "score: more RSS = higher");
    CHECK(oom_victim_score(&swap,&pl,&t) > oom_victim_score(&small,&pl,&t), "score: swap is counted");
    CHECK(oom_victim_score(&prot,&pl,&t) < 0, "score: protected = -1");
    CHECK(oom_victim_score(&immune,&pl,&t) < 0, "score: oom_score_adj=-1000 = -1");
    CHECK(oom_victim_score(&empty,&pl,&t) < 0, "score: rss=0 (kthread) = -1");
    CHECK(oom_victim_score(&init,&pl,&t) < 0, "score: pid<=1 = -1");
    CHECK(oom_victim_score(&self,&pl,&t) < 0, "score: the killer itself is untouchable");

    proc_sample a = {.pid=200,.rss_kb=1000000,.swap_kb=0,.oom_score_adj=500,.state='S',.comm="a"};
    proc_sample b = {.pid=201,.rss_kb=1000000,.swap_kb=0,.oom_score_adj=0,  .state='S',.comm="b"};
    CHECK(oom_victim_score(&a,&pl,&t) > oom_victim_score(&b,&pl,&t), "score: positive adj raises kill priority");

    /* adj is a multiplier, not an addend in megabytes */
    proc_sample helper = {.pid=202,.rss_kb=35044,.swap_kb=16908,.oom_score_adj=300,.state='S',.comm="steamwebhelper"};
    proc_sample hog    = {.pid=203,.rss_kb=393612,.swap_kb=84220,.oom_score_adj=0, .state='S',.comm="java"};
    CHECK(oom_victim_score(&hog,&pl,&t) > oom_victim_score(&helper,&pl,&t),
          "score: a 51 MB helper with adj=300 does not outrank a 470 MB process");
    proc_sample low = {.pid=204,.rss_kb=1000000,.swap_kb=0,.oom_score_adj=-500,.state='S',.comm="low"};
    CHECK(oom_victim_score(&low,&pl,&t) < oom_victim_score(&b,&pl,&t),
          "score: negative adj lowers kill priority");
}

static void test_smart_protection(void) {
    protect_list pl; oom_parse_protect("", &pl);
    thresholds t = base_th();

    /* GUI browser: 4 GB, running for two hours */
    proc_sample gui = {.pid=300,.rss_kb=4194304,.swap_kb=0,.oom_score_adj=0,.state='S',.comm="firefox",
                       .flags=PF_ENRICHED|PF_SESSION,.age_s=7200,.growth_kb=0};
    /* fresh build from a terminal: 1 GB, growing */
    proc_sample build = {.pid=301,.rss_kb=1048576,.swap_kb=0,.oom_score_adj=0,.state='R',.comm="rustc",
                         .flags=PF_ENRICHED|PF_TTY,.age_s=30,.growth_kb=204800};

    CHECK(oom_victim_score(&build,&pl,&t) > oom_victim_score(&gui,&pl,&t),
          "smart: a growing build is picked before a large GUI app");

    proc_sample procs[2] = {gui, build};
    CHECK(oom_pick_victim(procs, 2, &pl, &t) == 1, "smart: pick_victim picks the build");

    /* without smart protection raw size decides: the old behaviour */
    thresholds dumb = base_th(); dumb.protect_smart = 0;
    CHECK(oom_pick_victim(procs, 2, &pl, &dumb) == 0, "smart=0: selection by size is back");

    /* a long-running system service is protected more than a fresh process of the same size */
    proc_sample svc = {.pid=302,.rss_kb=1048576,.swap_kb=0,.oom_score_adj=0,.state='S',.comm="postgres",
                       .flags=PF_ENRICHED|PF_SYSTEM_SVC,.age_s=90000,.growth_kb=0};
    proc_sample fresh = {.pid=303,.rss_kb=1048576,.swap_kb=0,.oom_score_adj=0,.state='S',.comm="python",
                         .flags=PF_ENRICHED,.age_s=10,.growth_kb=0};
    CHECK(oom_victim_score(&fresh,&pl,&t) > oom_victim_score(&svc,&pl,&t),
          "smart: a fresh process is cheaper than a long-running service");
}

static void test_resident_relief(void) {
    thresholds t = base_th();
    protect_list pl; oom_parse_protect("", &pl);
    proc_sample cold = {.pid=700,.rss_kb=100*1024,.swap_kb=4096*1024,.comm="cold"};
    proc_sample hot = {.pid=701,.rss_kb=800*1024,.swap_kb=0,.comm="hot"};
    CHECK(oom_victim_score(&hot, &pl, &t) > oom_victim_score(&cold, &pl, &t),
          "resident relief: 4 GiB in swap must not outweigh 800 MiB resident");
}

static void test_decide_regression_psi_without_scarcity(void) {
    /* PSI from zram thrashing with 10 GB free once killed compilers.
     * Pressure without real scarcity must give WARN, not a kill. */
    thresholds t = base_th();
    mem_state thrash = {.psi_some_avg10=60.0,.psi_full_avg10=45.0,.mem_avail_kb=10L*1024*1024,
                        .mem_total_kb=19L*1024*1024,.swap_free_kb=1700*1024,.swap_total_kb=8192*1024};
    oom_verdict v = oom_decide_v2(&thrash, &t, 0.0, 0);
    CHECK(v.action == ACT_WARN, "regression: high PSI with free memory -> WARN, not kill");
    CHECK(v.reason == RS_THRASH, "regression: reason is thrashing, not starvation");
}

static void test_decide(void) {
    thresholds t = base_th();

    mem_state calm = {.psi_some_avg10=1.0,.psi_full_avg10=0.0,.mem_avail_kb=5000*1024,.mem_total_kb=19L*1024*1024};
    CHECK(oom_decide_v2(&calm,&t,0,0).action == ACT_NONE, "decide: calm -> NONE");

    mem_state soft_avail = {.psi_some_avg10=0.0,.psi_full_avg10=0.0,.mem_avail_kb=700*1024,.mem_total_kb=19L*1024*1024};
    oom_verdict sv = oom_decide_v2(&soft_avail,&t,0,0);
    CHECK(sv.action == ACT_SOFT && sv.reason == RS_AVAIL, "decide: avail<=soft -> SOFT/avail");

    mem_state hard_avail = {.psi_some_avg10=0.0,.psi_full_avg10=0.0,.mem_avail_kb=200*1024,.mem_total_kb=19L*1024*1024};
    oom_verdict hv = oom_decide_v2(&hard_avail,&t,0,0);
    CHECK(hv.action == ACT_HARD && hv.reason == RS_AVAIL, "decide: avail<=hard -> HARD at once");

    mem_state scarce_psi = {.psi_some_avg10=50.0,.psi_full_avg10=45.0,.mem_avail_kb=700*1024,.mem_total_kb=19L*1024*1024};
    CHECK(oom_decide_v2(&scarce_psi,&t,0,0).action == ACT_SOFT, "decide: PSI+scarcity, first sample -> SOFT");
    CHECK(oom_decide_v2(&scarce_psi,&t,0,2).action == ACT_HARD, "decide: PSI+scarcity sustained -> HARD");

    /* a high baseline (long load) raises the threshold: the same PSI is no longer a spike */
    CHECK(oom_decide_v2(&scarce_psi,&t,30.0,2).reason == RS_AVAIL,
          "decide: baseline 30 and k=2 give threshold 60, PSI 45 is not a spike");

    mem_state unknown = {.psi_some_avg10=0.0,.psi_full_avg10=0.0,.mem_avail_kb=-1,.mem_total_kb=0};
    CHECK(oom_decide_v2(&unknown,&t,0,0).action == ACT_NONE, "decide: avail unknown -> no kill");

    CHECK(oom_decide(&hard_avail,&t) == ACT_HARD, "decide: the old wrapper still works");
}

static void test_resolve_thresholds(void) {
    thresholds t = base_th();
    t.avail_soft_pct = 4.0; t.avail_hard_pct = 1.5;
    mem_state big = {.mem_total_kb = 19000000, .mem_avail_kb = 0};
    oom_resolve_thresholds(&big, &t);
    CHECK(t.avail_soft_kb == 760000, "thresholds: 4% of 19 GB = 760000 kB");
    CHECK(t.avail_hard_kb == 285000, "thresholds: 1.5% of 19 GB = 285000 kB");

    thresholds s = base_th();
    s.avail_soft_pct = 4.0; s.avail_hard_pct = 1.5;
    mem_state small = {.mem_total_kb = 2000000, .mem_avail_kb = 0};
    oom_resolve_thresholds(&small, &s);
    CHECK(s.avail_soft_kb == 384*1024, "thresholds: the lower soft clamp applies at 2 GB");
    CHECK(s.avail_hard_kb == 128*1024, "thresholds: the lower hard clamp applies at 2 GB");

    thresholds fixed = base_th();     /* pct=0 -> percentages do not touch the given MB */
    mem_state m = {.mem_total_kb = 19000000, .mem_avail_kb = 0};
    oom_resolve_thresholds(&m, &fixed);
    CHECK(fixed.avail_soft_kb == 800*1024 && fixed.avail_hard_kb == 300*1024,
          "thresholds: explicit MB take precedence over percentages");

    thresholds inv = base_th();
    inv.avail_soft_kb = 100*1024; inv.avail_hard_kb = 500*1024;
    oom_resolve_thresholds(&m, &inv);
    CHECK(inv.avail_soft_kb >= inv.avail_hard_kb, "thresholds: soft cannot be below hard");
}

static void test_baseline(void) {
    double b = 0;
    for (int i = 0; i < 500; i++) b = oom_update_baseline(b, 40.0, 0.02);
    CHECK(b > 39.0 && b <= 40.0, "baseline: converges to a constant load");
    double drop = oom_update_baseline(b, 0.0, 0.02);
    CHECK(drop < b && drop > 38.0, "baseline: a single zero does not drop the baseline");
    CHECK(oom_update_baseline(10.0, 10.0, 0.0) == 10.0, "baseline: alpha<=0 does not break the value");
}

static void test_parse_meminfo(void) {
    const char *buf =
        "MemTotal:       19000000 kB\n"
        "MemFree:         500000 kB\n"
        "MemAvailable:   12345678 kB\n"
        "SwapTotal:       8388604 kB\n"
        "SwapFree:        1740000 kB\n";
    CHECK(oom_parse_meminfo_avail(buf) == 12345678, "meminfo: MemAvailable read");
    CHECK(oom_parse_meminfo_field(buf, "MemTotal:") == 19000000, "meminfo: MemTotal read");
    CHECK(oom_parse_meminfo_field(buf, "SwapFree:") == 1740000, "meminfo: SwapFree read");
    CHECK(oom_parse_meminfo_avail("MemTotal: 100 kB\n") == -1, "meminfo: no MemAvailable -> -1");
}

static void test_parse_psi(void) {
    const char *buf =
        "some avg10=2.13 avg60=0.06 avg300=5.31 total=208556838\n"
        "full avg10=1.07 avg60=0.06 avg300=5.24 total=204391349\n";
    double s = -1, f = -1;
    CHECK(oom_parse_psi_line(buf, "some", &s) == 0 && s > 2.1 && s < 2.2, "psi: some avg10=2.13");
    CHECK(oom_parse_psi_line(buf, "full", &f) == 0 && f > 1.06 && f < 1.08, "psi: full avg10=1.07");
    double x = -1;
    CHECK(oom_parse_psi_line("garbage\n", "some", &x) == -1, "psi: garbage -> -1");
}

static void test_parse_status(void) {
    const char *buf =
        "Name:\tbrowser\n" "Umask:\t0022\n" "State:\tR (running)\n"
        "Tgid:\t4821\n" "VmRSS:\t  2097152 kB\n" "VmSwap:\t   419840 kB\n";
    proc_sample p; memset(&p, 0, sizeof p);
    oom_parse_status(buf, &p);
    CHECK(strcmp(p.comm, "browser") == 0, "status: Name");
    CHECK(p.state == 'R', "status: State R");
    CHECK(p.rss_kb == 2097152, "status: VmRSS");
    CHECK(p.swap_kb == 419840, "status: VmSwap");

    const char *evil =
        "Name:\tVmRSS:evil\n" "State:\tR (running)\n"
        "VmRSS:\t  2097152 kB\n" "VmSwap:\t       0 kB\n";
    proc_sample e; memset(&e, 0, sizeof e);
    oom_parse_status(evil, &e);
    CHECK(strcmp(e.comm, "VmRSS:evil") == 0, "status: a comm containing 'VmRSS:' is read as a name");
    CHECK(e.rss_kb == 2097152, "status: the real VmRSS is read, the comm does not shadow it");
}

static void test_parse_stat(void) {
    /* comm with parentheses and spaces: the parser must start from the last ')' */
    const char *buf = "4321 (my (weird) proc) S 1 4321 4321 34816 4321 4194304 "
                      "100 0 0 0 5 5 0 0 20 0 3 0 987654 12345678\n";
    int tty = -1; unsigned long long start = 0;
    CHECK(oom_parse_stat(buf, &tty, &start) == 0, "stat: parsed");
    CHECK(tty == 34816, "stat: tty_nr = field 7");
    CHECK(start == 987654ULL, "stat: starttime = field 22");

    const char *no_tty = "10 (kthreadd) S 2 0 0 0 -1 69238880 "
                         "0 0 0 0 0 0 0 0 20 0 1 0 5 0\n";
    CHECK(oom_parse_stat(no_tty, &tty, &start) == 0 && tty == 0, "stat: kthread without a tty");
    CHECK(oom_parse_stat("garbage without parentheses", &tty, &start) == -1, "stat: garbage -> -1");
}

static void test_classify_cgroup(void) {
    char out[OOM_CGROUP_MAX];
    unsigned f = oom_classify_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n", out, sizeof out);
    CHECK((f & PF_SESSION) == 0, "cgroup: user.slice alone is not a GUI marker");
    CHECK(strstr(out, "session-2.scope") != 0, "cgroup: path kept");

    f = oom_classify_cgroup("0::/system.slice/nginx.service\n", out, sizeof out);
    CHECK((f & PF_SYSTEM_SVC) != 0, "cgroup: system.slice -> PF_SYSTEM_SVC");
    CHECK((f & PF_SESSION) == 0, "cgroup: a service is not a session");

    char tiny[16];
    unsigned tf = oom_classify_cgroup("0::/user.slice/user-1000.slice/app.slice/app-kitty-abc.scope\n", tiny, sizeof tiny);
    CHECK(strlen(tiny) == 15, "cgroup: a long path is truncated to the buffer");
    CHECK(strchr(tiny, '\n') == 0, "cgroup: no newline in the output");
    CHECK((tf & PF_CG_TRUNC) != 0, "cgroup: truncation is flagged, such a path is never killed");

    char room[128];
    unsigned ff = oom_classify_cgroup("0::/system.slice/nginx.service\n", room, sizeof room);
    CHECK((ff & PF_CG_TRUNC) == 0, "cgroup: path fits, no truncation flag");
}

static void test_link_is_gui(void) {
    CHECK(oom_link_is_gui("/dev/dri/renderD128") == 1, "gui-fd: renderD128 -> GUI");
    CHECK(oom_link_is_gui("/dev/dri/card1") == 1, "gui-fd: card1 -> GUI");
    CHECK(oom_link_is_gui("/tmp/build/out.o") == 0, "gui-fd: regular file -> no");
    CHECK(oom_link_is_gui("socket:[12345]") == 0, "gui-fd: socket -> no");
    CHECK(oom_link_is_gui("/dev/dri") == 0, "gui-fd: the directory itself without a node -> no");
}

static void test_cgroup_killable(void) {
    CHECK(oom_cgroup_killable("/user.slice/user-1000.slice/app.slice/app-build.scope") == 1,
          "cgroup-kill: leaf app-*.scope allowed");
    CHECK(oom_cgroup_killable("/system.slice/nginx.service") == 1,
          "cgroup-kill: leaf service allowed");
    CHECK(oom_cgroup_killable("/user.slice/user-1000.slice/session-2.scope") == 0,
          "cgroup-kill: login session refused");
    CHECK(oom_cgroup_killable("/user.slice/user-1000.slice/user@1000.service") == 0,
          "cgroup-kill: user manager refused");
    CHECK(oom_cgroup_killable("/user.slice/user-1000.slice") == 0,
          "cgroup-kill: slice (branch) refused");
    CHECK(oom_cgroup_killable("/init.scope") == 0, "cgroup-kill: init.scope refused");
    CHECK(oom_cgroup_killable("/system.slice/aegis-oom.service") == 0,
          "cgroup-kill: ourselves refused");
    CHECK(oom_cgroup_killable("") == 0, "cgroup-kill: empty path refused");
}

static void test_parse_zram(void) {
    const char *buf = "9320448000 3221225472 3300000000 8589934592 3400000000 12345 0 678 0\n";
    long o = -1, c = -1, t = -1;
    CHECK(oom_parse_zram_mmstat(buf, &o, &c, &t) == 0, "zram: parsed");
    CHECK(o == 9320448000L/1024, "zram: orig in kB");
    CHECK(oom_parse_zram_mmstat("1 2\n", &o, &c, &t) == -1, "zram: too few fields -> -1");
}

static void test_ties_and_limits(void) {
    thresholds t = base_th(); t.protect_smart = 0;
    protect_list pl; oom_parse_protect("", &pl);
    proc_sample same[3] = {
        {.pid=500,.rss_kb=500000,.comm="java"},
        {.pid=501,.rss_kb=500000,.comm="firefox"},
        {.pid=502,.rss_kb=500000,.comm="steamwebhelper"},
    };
    CHECK(oom_pick_victim(same, 3, &pl, &t) == 0, "ties: equal scores keep the first candidate");
    oom_parse_protect("java,firefox,steamwebhelper", &pl);
    CHECK(oom_pick_victim(same, 3, &pl, &t) == -1, "ties: all protected gives no victim");
    CHECK(oom_pick_victim(same, 0, &pl, &t) == -1, "ties: an empty list gives no victim");

    char csv[64 * 8] = "";
    for (int i = 0; i < OOM_MAX_PROTECT + 5; i++) {
        char name[8]; snprintf(name, sizeof name, "p%d,", i); strcat(csv, name);
    }
    CHECK(oom_parse_protect(csv, &pl) == OOM_MAX_PROTECT, "protect: the list stops at its capacity");
    CHECK(oom_is_protected("p0", &pl) && !oom_is_protected("p40", &pl), "protect: first names kept, extra dropped");
    char longname[64]; memset(longname, 'x', sizeof longname - 1); longname[63] = 0;
    oom_parse_protect(longname, &pl);
    CHECK(strlen(pl.names[0]) == OOM_COMM_MAX - 1, "protect: a long name is cut to the comm buffer");

    proc_sample init = {.pid=1,.rss_kb=9000000,.comm="systemd"};
    proc_sample zero = {.pid=0,.rss_kb=9000000,.comm="swapper"};
    oom_parse_protect("", &pl);
    CHECK(oom_victim_score(&init, &pl, &t) < 0 && oom_victim_score(&zero, &pl, &t) < 0,
          "guards: PID 1 and PID 0 never score, even with smart protection off");
}

int main(void) {
    test_ties_and_limits();
    test_parse_protect();
    test_is_protected();
    test_victim_score();
    test_smart_protection();
    test_resident_relief();
    test_decide_regression_psi_without_scarcity();
    test_decide();
    test_resolve_thresholds();
    test_baseline();
    test_parse_meminfo();
    test_parse_psi();
    test_parse_status();
    test_parse_stat();
    test_classify_cgroup();
    test_link_is_gui();
    test_cgroup_killable();
    test_parse_zram();
    if (g_fail) { printf("%d checks failed\n", g_fail); return 1; }
    printf("OK: oom_policy, all checks passed\n");
    return 0;
}
