/* Exercise the real configuration/action boundary without starting a daemon. */
#define main oom_daemon_main
#include "oom.c"
#undef main
#include <sys/wait.h>

static int failures;
#define EXPECT(c, message) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", message); failures++; } } while (0)

static void config_protect(void) {
    apply_conf_line("AEG_OOM_PROTECT=\"java,firefox\" # keep the whole application");
    EXPECT(oom_is_protected("java", &g_pl), "quoted first protected name");
    EXPECT(oom_is_protected("firefox", &g_pl), "comment does not enter protected name");
    apply_conf_line("AEG_OOM_PROTECT=java,firefox   # comment");
    EXPECT(oom_is_protected("firefox", &g_pl), "unquoted inline comment is stripped");
}

static void stale_action(void) {
    memset(&g_procs[0], 0, sizeof g_procs[0]);
    g_procs[0].pid = (int)getpid();
    g_procs[0].start_ticks = 1; /* deliberately not this process */
    g_procs[0].rss_kb = 1024;
    g_dryrun = 1;
    g_lastkill[0] = 0;
    oom_verdict v = {.action=ACT_HARD, .reason=RS_FORCED};
    mem_state m = {.mem_total_kb=1024*1024, .mem_avail_kb=1024};
    act_kill(0, &v, &m);
    EXPECT(!g_lastkill[0], "cancelled action must not be reported as lastkill");
}

static void process_identity_and_tree(void) {
    prev_foot_put(123, 100, 999);
    EXPECT(prev_foot_get(123, 100) == 999, "same process retains growth baseline");
    EXPECT(prev_foot_get(123, 101) == -1, "PID reuse resets growth baseline");
    memset(g_procs, 0, 4 * sizeof g_procs[0]);
    g_procs[0] = (proc_sample){.pid=10,.ppid=1,.comm="java"};
    g_procs[1] = (proc_sample){.pid=11,.ppid=10,.comm="node"};
    g_procs[2] = (proc_sample){.pid=12,.ppid=1,.comm="sway"};
    g_procs[3] = (proc_sample){.pid=13,.ppid=12,.comm="game"};
    oom_parse_protect("java,sway", &g_pl);
    inherit_protection(4);
    EXPECT(g_procs[1].flags & PF_PROTECTED_TREE, "application children inherit protection");
    EXPECT(!(g_procs[3].flags & PF_PROTECTED_TREE), "compositor protection must not shield every application");
}

static void invalid_intervals_are_safe(void) {
    g_refresh_ms = 0; g_idle_ms = -1; g_rate_ms = 0;
    g_th.sustain_n = -5; g_th.psi_soft = 1000;
    validate_runtime_settings();
    EXPECT(g_refresh_ms >= 100 && g_idle_ms >= g_refresh_ms && g_rate_ms >= 100,
           "invalid timing cannot create a zero-timeout RT busy loop");
    EXPECT(g_th.sustain_n >= 1 && g_th.psi_soft <= 100, "invalid pressure settings bounded");
}

static void invalid_environment_cannot_arm(void) {
    setenv("AEG_OOM_DRYRUN", "0garbage", 1);
    setenv("AEG_OOM_PSI_SOFT", "7x", 1);
    load_env();
    EXPECT(g_dryrun == 1, "invalid environment suffix must not turn dry-run off");
    EXPECT(g_th.psi_soft == 20, "floating environment suffix is rejected");
    setenv("AEG_OOM_DRYRUN", "0 # intentional inline comment", 1);
    setenv("AEG_OOM_PSI_SOFT", "1.5\t# comment", 1);
    load_env();
    EXPECT(g_dryrun == 0, "EnvironmentFile inline comments remain supported");
    EXPECT(g_th.psi_soft == 1.5, "floating environment comments remain supported");
    setenv("AEG_OOM_DRYRUN", "2", 1);
    load_env();
    EXPECT(g_dryrun == 1, "out of range dry run keeps the default");
    unsetenv("AEG_OOM_DRYRUN"); unsetenv("AEG_OOM_PSI_SOFT");
    setenv("AEG_OOM_AVAIL_SOFT_MB", "900", 1);
    load_env();
    EXPECT(g_th.avail_soft_kb == 900 * 1024 && g_th.avail_soft_pct == 0 && g_th.avail_hard_pct == 1.5,
           "explicit megabytes replace only their own percentage");
    unsetenv("AEG_OOM_AVAIL_SOFT_MB");
    load_env();
    EXPECT(g_th.avail_soft_kb == 0 && g_th.avail_soft_pct == 4, "defaults come back without the variable");
}

static void complete_candidate_selection(void) {
    oom_parse_protect("", &g_pl);
    memset(g_procs, 0, 33 * sizeof g_procs[0]);
    g_th.protect_smart = 1;
    for (int i = 0; i < 32; i++)
        g_procs[i] = (proc_sample){.pid=2000000000+i,.rss_kb=1000000,
            .flags=PF_ENRICHED|PF_SESSION,.age_s=90000};
    EXPECT(read_proc((int)getpid(), &g_procs[32]) == 0, "read test process");
    g_procs[32].rss_kb = 200000;
    int vi = select_victim(33);
    EXPECT(vi == 32 && (g_procs[32].flags & PF_ENRICHED), "winner beyond top 32 is enriched before action");
}

static void soft_escalates_after_term_grace(void) {
    int pipes[2]; EXPECT(!pipe(pipes), "signal fixture pipe");
    pid_t child = fork();
    if (!child) {
        close(pipes[0]); signal(SIGTERM, SIG_IGN);
        (void)write(pipes[1], "r", 1); close(pipes[1]);
        for (;;) pause();
    }
    close(pipes[1]); char ready;
    EXPECT(child > 0 && read(pipes[0], &ready, 1) == 1, "signal fixture ready"); close(pipes[0]);
    if (child <= 0) return;
    EXPECT(!read_proc((int)child, &g_procs[0]), "read signal fixture identity");
    g_dryrun = 0; g_cgroup_kill = 0;
    oom_parse_protect("", &g_pl);
    g_last_kill_pid = (int)child; g_last_kill_start = g_procs[0].start_ticks;
    g_last_kill_ms = now_ms() - 9000; g_last_signal = SIGTERM; g_term_grace_ms = 8000;
    oom_verdict v = {.action=ACT_SOFT, .reason=RS_AVAIL};
    mem_state m = {.mem_avail_kb=500*1024,.mem_total_kb=19L*1024*1024};
    act_kill(0, &v, &m);
    int status = 0; pid_t done = 0;
    for (int i = 0; i < 100 && !done; i++) { usleep(10000); done = waitpid(child, &status, WNOHANG); }
    EXPECT(done == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
           "a SIGTERM ignored past the grace escalates to SIGKILL");
    EXPECT(strstr(g_lastkill, "SIGKILL") != NULL, "the escalation is reported as SIGKILL");
    if (!done) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    if (g_pending_pidfd >= 0) { close(g_pending_pidfd); g_pending_pidfd = -1; }
}

static void signal_choice(void) {
    proc_sample p = {.pid=4242,.start_ticks=7};
    oom_verdict soft = {.action=ACT_SOFT}, hard = {.action=ACT_HARD};
    g_dryrun = 0; g_rate_ms = 2000; g_term_grace_ms = 8000; g_pending_pidfd = -1;
    long t = now_ms();
    g_last_kill_pid = 0; g_last_kill_ms = 0;
    EXPECT(choose_signal(&p, &soft, t) == SIGTERM, "first SOFT request is SIGTERM");
    EXPECT(choose_signal(&p, &hard, t) == SIGKILL, "HARD request is SIGKILL");
    g_last_kill_pid = 99; g_last_kill_ms = t - 500;
    EXPECT(choose_signal(&p, &hard, t) == 0, "rate limit holds any kill");
    g_last_kill_pid = 4242; g_last_kill_start = 7; g_last_signal = SIGTERM; g_last_kill_ms = t - 3000;
    EXPECT(choose_signal(&p, &soft, t) == 0, "repeat SOFT waits for the TERM grace");
    g_last_kill_ms = t - 9000;
    EXPECT(choose_signal(&p, &soft, t) == SIGKILL, "repeat SOFT after the grace escalates");
    g_last_kill_pid = 0; g_last_kill_ms = 0;
}

int main(void) {
    signal_choice();
    config_protect();
    stale_action();
    process_identity_and_tree();
    invalid_intervals_are_safe();
    invalid_environment_cannot_arm();
    complete_candidate_selection();
    soft_escalates_after_term_grace();
    if (failures) return 1;
    puts("OK: oom runtime");
    return 0;
}
