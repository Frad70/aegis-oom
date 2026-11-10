/* aegis-oom: pre-armed userspace OOM killer.
 * The policy lives in oom_policy.c. This file is the mechanism: PSI epoll
 * trigger, /proc scan, candidate enrichment, kill and the state file.
 * Hardened like the reaper: oom_score_adj=-1000, mlockall and SCHED_FIFO.
 */
#define _GNU_SOURCE
#include "oom_policy.h"
#include "config_value.h"
#include "cgroup_guard.h"
#include "aeg_common.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <poll.h>
#include <math.h>

#define ENRICH_TOP 32            /* enrich only the largest candidates; the rest cannot win */
#define PREV_SLOTS 16384         /* pid -> previous-cycle footprint hash (power of two) */

/* config: environment, then the config file, then flags; SIGHUP rereads the file */
static protect_list g_pl;
static thresholds   g_th;
static int          g_dryrun = 1;
static int          g_arm = 1;
static const char  *g_scope = 0;         /* cgroup dir, or NULL = all of /proc */
static const char  *g_state_path = "/run/aegis/oom.state";
static const char  *g_psi_path = "/sys/fs/cgroup/memory.pressure"; /* root cgroup PSI is system wide and accepts triggers; /proc/pressure/memory rejects them on some 6.x kernels */
static const char  *g_conf_path = "/etc/aegis/aegis-oom.conf";
static long         g_psi_window_us = 1000000;
static long         g_psi_stall_us  = 150000;
static int          g_refresh_ms = 1500;
static int          g_idle_ms = 6000;          /* idle cycle: meminfo+PSI only, no /proc scan */
static int          g_idle_scan_s = 60;        /* how often to refresh the candidate snapshot while idle */
static const char  *g_watch_path = "/run/aegis/watch";  /* a monitor touches this file to keep the hot cycle */
static long         g_rate_ms = 2000;
static double       g_baseline_alpha = 0.02;   /* ~5 minutes of memory at a 1.5 s cycle */
static int          g_cgroup_kill = 0;         /* kill the whole leaf cgroup instead of one PID */
static int          g_cli_protect, g_cli_dryrun, g_cli_state;
static int          g_no_conf;
static int          g_learning = 1;
static char         g_state_conf[512];
static long         g_term_grace_ms = 8000;
static oom_action   g_force = ACT_NONE;   /* only with --once and --scope */

/* static buffers: no allocations on the hot path */
static proc_sample g_procs[OOM_MAX_PROCS];
static int         g_idx[OOM_MAX_PROCS];
static char        g_rbuf[64*1024];
static char        g_dbuf[64*1024];
static char        g_wbuf[256*1024];
static char        g_lastkill[512] = "";
static long        g_last_kill_ms = 0;
static int         g_last_kill_pid = 0;
static unsigned long long g_last_kill_start;
static int         g_last_signal;
static long        g_last_dry_ms;

static int  g_prev_pid[PREV_SLOTS];
static long g_prev_foot[PREV_SLOTS];
static unsigned long long g_prev_start[PREV_SLOTS];
static int g_pid_index[PREV_SLOTS];

static double g_baseline = 0.0;
static int    g_sustain = 0;
static long   g_hz = 100;
static int    g_self_pid = 0;
static const char *g_learn_path = "/var/lib/aegis/learned";


static int numeric_tail(const char *tail) {
    while (*tail == ' ' || *tail == '\t') tail++;
    return !*tail || *tail == '#' || *tail == '\r' || *tail == '\n';
}

static double env_d(const char *k, double def) {
    const char *v = getenv(k); char *end = NULL;
    if (!v) return def;
    errno = 0; double n = strtod(v, &end);
    return errno || end == v || !numeric_tail(end) || !isfinite(n) ? def : n;
}
static long env_l(const char *k, long def) {
    const char *v = getenv(k); char *end = NULL;
    if (!v) return def;
    errno = 0; long n = strtol(v, &end, 10);
    return errno || end == v || !numeric_tail(end) || n < 0 || n > INT_MAX ? def : n;
}

static void validate_runtime_settings(void) {
    if (g_refresh_ms < 100 || g_refresh_ms > 60000) g_refresh_ms = 1500;
    if (g_idle_ms < g_refresh_ms) g_idle_ms = g_refresh_ms;
    if (g_idle_ms > 60000) g_idle_ms = 60000;
    if (g_idle_scan_s < 1 || g_idle_scan_s > 3600) g_idle_scan_s = 60;
    if (g_rate_ms < 100 || g_rate_ms > 60000) g_rate_ms = 2000;
    if (g_term_grace_ms < 1000 || g_term_grace_ms > 60000) g_term_grace_ms = 8000;
    if (g_dryrun < 0 || g_dryrun > 1) g_dryrun = 1;
    if (g_cgroup_kill < 0 || g_cgroup_kill > 1) g_cgroup_kill = 0;
    if (g_th.sustain_n < 1 || g_th.sustain_n > 120) g_th.sustain_n = 3;
    if (g_th.psi_soft < 0.1 || g_th.psi_soft > 100) g_th.psi_soft = 20;
    if (g_th.psi_hard < 0.1 || g_th.psi_hard > 100) g_th.psi_hard = 40;
    if (g_th.baseline_k < 1 || g_th.baseline_k > 100) g_th.baseline_k = 2;
    if (g_th.avail_soft_pct < 0 || g_th.avail_soft_pct > 90) g_th.avail_soft_pct = 4;
    if (g_th.avail_hard_pct < 0 || g_th.avail_hard_pct > 90) g_th.avail_hard_pct = 1.5;
    if (g_baseline_alpha < 0.0001 || g_baseline_alpha > 1) g_baseline_alpha = 0.02;
    if (g_psi_window_us < 500000 || g_psi_window_us > 10000000) g_psi_window_us = 1000000;
    if (g_psi_stall_us < 1 || g_psi_stall_us >= g_psi_window_us) g_psi_stall_us = g_psi_window_us / 2;
}


static long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void read_mem_state(mem_state *m) {
    memset(m, 0, sizeof *m);
    m->mem_avail_kb = -1; m->psi_some_avg10 = 0; m->psi_full_avg10 = 0;
    m->mem_total_kb = 0; m->swap_free_kb = -1; m->swap_total_kb = 0;
    if (read_file("/proc/meminfo", g_rbuf, sizeof g_rbuf) >= 0) {
        m->mem_avail_kb  = oom_parse_meminfo_avail(g_rbuf);
        long v;
        if ((v = oom_parse_meminfo_field(g_rbuf, "MemTotal:"))  > 0) m->mem_total_kb  = v;
        if ((v = oom_parse_meminfo_field(g_rbuf, "SwapFree:"))  >= 0) m->swap_free_kb  = v;
        if ((v = oom_parse_meminfo_field(g_rbuf, "SwapTotal:")) > 0) m->swap_total_kb = v;
        m->zswap_kb = oom_parse_meminfo_field(g_rbuf, "Zswap:");
        m->cached_kb = oom_parse_meminfo_field(g_rbuf, "Cached:");
        m->sreclaimable_kb = oom_parse_meminfo_field(g_rbuf, "SReclaimable:");
    }
    if (read_file(g_psi_path, g_rbuf, sizeof g_rbuf) >= 0) {
        oom_parse_psi_line(g_rbuf, "some", &m->psi_some_avg10);
        oom_parse_psi_line(g_rbuf, "full", &m->psi_full_avg10);
    }
}

static void read_zram(long *o, long *c, long *t) {
    *o = *c = *t = 0;
    if (read_file("/sys/block/zram0/mm_stat", g_rbuf, sizeof g_rbuf) >= 0)
        oom_parse_zram_mmstat(g_rbuf, o, c, t);
}

static long uptime_s(void) {
    if (read_file("/proc/uptime", g_rbuf, sizeof g_rbuf) < 0) return 0;
    return (long)atof(g_rbuf);
}

/* previous footprints: a growing process matters more than its absolute size */
static unsigned prev_slot(int pid) { return ((unsigned)pid * 2654435761u) & (PREV_SLOTS - 1); }

static long prev_foot_get(int pid, unsigned long long start) {
    unsigned s = prev_slot(pid);
    for (int i = 0; i < 8; i++) {
        unsigned k = (s + (unsigned)i) & (PREV_SLOTS - 1);
        if (g_prev_pid[k] == pid) return g_prev_start[k] == start ? g_prev_foot[k] : -1;
        if (g_prev_pid[k] == 0) return -1;
    }
    return -1;
}

static void prev_foot_put(int pid, unsigned long long start, long foot) {
    unsigned s = prev_slot(pid);
    for (int i = 0; i < 8; i++) {
        unsigned k = (s + (unsigned)i) & (PREV_SLOTS - 1);
        if (g_prev_pid[k] == pid || g_prev_pid[k] == 0) {
            g_prev_pid[k] = pid; g_prev_start[k] = start; g_prev_foot[k] = foot; return;
        }
    }
    unsigned k = s;                       /* probe window full: evict the first slot */
    g_prev_pid[k] = pid; g_prev_start[k] = start; g_prev_foot[k] = foot;
}

static int read_proc(int pid, proc_sample *s) {
    char path[256];
    memset(s, 0, sizeof *s);
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int initial_tty; unsigned long long initial_start;
    if (read_file(path, g_rbuf, sizeof g_rbuf) < 0 ||
        oom_parse_stat(g_rbuf, &initial_tty, &initial_start) != 0 || !initial_start) return -1;
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    if (read_file(path, g_rbuf, sizeof g_rbuf) < 0) return -1;
    oom_parse_status(g_rbuf, s);
    s->pid = pid;
    s->flags = 0; s->age_s = -1; s->growth_kb = 0; s->cgroup[0] = 0;
    snprintf(path, sizeof path, "/proc/%d/oom_score_adj", pid);
    char b[32]; s->oom_score_adj = 0;
    if (read_file(path, b, sizeof b) >= 0) s->oom_score_adj = atoi(b);
    if (pid == g_self_pid) s->flags |= PF_SELF;

    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int tty = 0;
    if (read_file(path, g_rbuf, sizeof g_rbuf) < 0 ||
        oom_parse_stat(g_rbuf, &tty, &s->start_ticks) != 0 || s->start_ticks != initial_start) return -1;
    if (tty) s->flags |= PF_TTY;

    long foot = s->rss_kb + s->swap_kb;
    long prev = prev_foot_get(pid, s->start_ticks);
    if (prev >= 0 && foot > prev) s->growth_kb = foot - prev;
    prev_foot_put(pid, s->start_ticks, foot);
    return 0;
}

/* the fd list is read only for the top candidates: expensive, and needed only there */
static int has_gui_fd(int pid) {
    char path[256];
    snprintf(path, sizeof path, "/proc/%d/fd", pid);
    int dfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return 0;
    char buf[8192], link[256];
    int found = 0, seen = 0;
    while (!found && seen < 512) {
        long r = syscall(SYS_getdents64, dfd, buf, sizeof buf);
        if (r <= 0) break;
        for (long off = 0; off < r; ) {
            struct ld64 *e = (struct ld64 *)(buf + off);
            off += e->d_reclen;
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            if (++seen > 512) break;
            ssize_t k = readlinkat(dfd, e->d_name, link, sizeof link - 1);
            if (k > 0) { link[k] = 0; if (oom_link_is_gui(link)) { found = 1; break; } }
        }
    }
    close(dfd);
    return found;
}

static void enrich(proc_sample *s, long up) {
    char path[256];
    int tty = 0; unsigned long long start = 0;
    snprintf(path, sizeof path, "/proc/%d/stat", s->pid);
    if (read_file(path, g_rbuf, sizeof g_rbuf) >= 0 && oom_parse_stat(g_rbuf, &tty, &start) == 0) {
        if (tty != 0) s->flags |= PF_TTY;
        long age = up - (long)(start / (unsigned long long)g_hz);
        s->age_s = age > 0 ? age : 0;
        if (s->start_ticks && start != s->start_ticks) { s->rss_kb = 0; return; }
        s->start_ticks = start;
    } else { s->rss_kb = 0; return; }
    snprintf(path, sizeof path, "/proc/%d/cgroup", s->pid);
    if (read_file(path, g_rbuf, sizeof g_rbuf) >= 0)
        s->flags |= oom_classify_cgroup(g_rbuf, s->cgroup, OOM_CGROUP_MAX);
    if ((s->flags & PF_FROZEN) && !(s->flags & PF_CG_TRUNC)) {
        snprintf(path, sizeof path, "/sys/fs/cgroup%s/cgroup.freeze", s->cgroup);
        char frozen[32];
        if (read_file(path, frozen, sizeof frozen) >= 0 && atoi(frozen) == 0) s->flags &= ~PF_FROZEN;
    }

    if (has_gui_fd(s->pid)) s->flags |= PF_SESSION;
    s->flags |= PF_ENRICHED;
}

static int scan_proc_dir(void) {
    int n = 0;
    int fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return 0;
    for (;;) {
        long r = syscall(SYS_getdents64, fd, g_dbuf, sizeof g_dbuf);
        if (r <= 0) break;
        for (long off = 0; off < r && n < OOM_MAX_PROCS; ) {
            struct ld64 *e = (struct ld64 *)(g_dbuf + off);
            off += e->d_reclen;
            const char *nm = e->d_name;
            if (nm[0] < '1' || nm[0] > '9') continue;
            int pid = atoi(nm);
            if (pid > 0 && read_proc(pid, &g_procs[n]) == 0) n++;
        }
    }
    close(fd);
    return n;
}

static int scan_all(void) {
    if (g_scope) {
        char path[512]; snprintf(path, sizeof path, "%s/cgroup.procs", g_scope);
        if (read_file(path, g_dbuf, sizeof g_dbuf) < 0) return 0;
        int n = 0; char *p = g_dbuf;
        while (*p && n < OOM_MAX_PROCS) {
            int pid = atoi(p);
            if (pid > 0 && read_proc(pid, &g_procs[n]) == 0) n++;
            char *nl = strchr(p, '\n'); if (!nl) break; p = nl + 1;
        }
        return n;
    }
    return scan_proc_dir();
}

static void inherit_protection(int n) {
    memset(g_pid_index, 0, sizeof g_pid_index);
    for (int i = 0; i < n; i++) {
        unsigned k = prev_slot(g_procs[i].pid);
        while (g_pid_index[k]) k = (k + 1) & (PREV_SLOTS - 1);
        g_pid_index[k] = i + 1;
    }
    for (int i = 0; i < n; i++) {
        proc_sample *p = &g_procs[i];
        for (int depth = 0; depth < 64; depth++) {
            if (depth && oom_ancestry_boundary(p->comm)) break;
            if ((p->flags & PF_PROTECTED_TREE) || oom_is_protected(p->comm, &g_pl) || p->oom_score_adj <= OOM_ADJ_IMMUNE) {
                g_procs[i].flags |= PF_PROTECTED_TREE;
                break;
            }
            unsigned k = prev_slot(p->ppid);
            while (g_pid_index[k] && g_procs[g_pid_index[k]-1].pid != p->ppid)
                k = (k + 1) & (PREV_SLOTS - 1);
            if (!g_pid_index[k] || &g_procs[g_pid_index[k]-1] == p) break;
            p = &g_procs[g_pid_index[k]-1];
        }
    }
}

/* Enrichment can lower a score, revealing a candidate beyond the first 32.
 * Re-rank until the actual winner has been checked, with no arbitrary cutoff. */
static int select_victim(int n) {
    inherit_protection(n);
    long up = uptime_s();
    for (int i = 0; i < n; i++) {
        int vi = oom_pick_victim(g_procs, n, &g_pl, &g_th);
        if (vi < 0 || (g_procs[vi].flags & PF_ENRICHED)) return vi;
        enrich(&g_procs[vi], up);
    }
    return oom_pick_victim(g_procs, n, &g_pl, &g_th);
}

static thresholds cycle_thresholds(const mem_state *m) {
    thresholds th = g_th; /* the configured percentages stay intact */
    oom_resolve_thresholds(m, &th);
    return th;
}

static int cmp_foot(const void *a, const void *b) {
    const proc_sample *pa = &g_procs[*(const int *)a], *pb = &g_procs[*(const int *)b];
    long fa = pa->rss_kb + pa->swap_kb, fb = pb->rss_kb + pb->swap_kb;
    return (fb > fa) - (fb < fa);
}

/* enrich the largest candidates: only they can become the victim */
static void enrich_top(int n) {
    if (n <= 0) return;
    long up = uptime_s();
    for (int i = 0; i < n; i++) g_idx[i] = i;
    qsort(g_idx, (size_t)n, sizeof(int), cmp_foot);
    int lim = n < ENRICH_TOP ? n : ENRICH_TOP;
    for (int j = 0; j < lim; j++) {
        proc_sample *p = &g_procs[g_idx[j]];
        if (p->rss_kb <= 0) continue;
        enrich(p, up);
    }
}

static int cmp_score(const void *a, const void *b) {
    long sa = oom_victim_score(&g_procs[*(const int *)a], &g_pl, &g_th);
    long sb = oom_victim_score(&g_procs[*(const int *)b], &g_pl, &g_th);
    return (sb > sa) - (sb < sa);
}

static const char *reason_name(oom_reason r) {
    return r == RS_AVAIL ? "avail" : r == RS_PSI_SCARCE ? "psi+scarce" :
           r == RS_THRASH ? "thrash" : r == RS_FORCED ? "forced" : "none";
}

static const char *action_name(oom_action a) {
    return a == ACT_HARD ? "hard" : a == ACT_SOFT ? "soft" : a == ACT_WARN ? "warn" : "none";
}

static void write_state(int n, const mem_state *m, const oom_verdict *v, int scan_age_s) {
    long zo, zc, zt; read_zram(&zo, &zc, &zt);
    int len = 0;
    len += snprintf(g_wbuf + len, sizeof g_wbuf - len,
        "# aegis-oom state v4\nmode %s\nlevel %s\nreason %s\n"
        "psi_some10 %.2f\npsi_full10 %.2f\npsi_baseline %.2f\nsustain %d\n"
        "mem_avail_kb %ld\nmem_total_kb %ld\navail_soft_kb %ld\navail_hard_kb %ld\n"
        "swap_free_kb %ld\nzram_orig_kb %ld\nzram_compr_kb %ld\nzram_total_kb %ld\n"
        "scan_age_s %d\n"
        "zswap_kb %ld\ncached_kb %ld\nsreclaimable_kb %ld\nswap_total_kb %ld\n",
        g_dryrun ? "dryrun" : "live", action_name(v->action), reason_name(v->reason),
        m->psi_some_avg10, m->psi_full_avg10, v->psi_baseline, g_sustain,
        m->mem_avail_kb, m->mem_total_kb, v->avail_soft_kb, v->avail_hard_kb,
        m->swap_free_kb, zo, zc, zt, scan_age_s,
        m->zswap_kb, m->cached_kb, m->sreclaimable_kb, m->swap_total_kb);
    if (len >= (int)sizeof g_wbuf) len = (int)sizeof g_wbuf - 1;
    for (int i = 0; i < n; i++) g_idx[i] = i;
    qsort(g_idx, (size_t)n, sizeof(int), cmp_score);
    int rank = 0;
    for (int j = 0; j < n && len < (int)sizeof g_wbuf - 512; j++) {
        proc_sample *p = &g_procs[g_idx[j]];
        if (p->rss_kb <= 0) continue;
        long s = oom_victim_score(p, &g_pl, &g_th);
        char vb[24];
        const char *verdict;
        if (s < 0) verdict = "protected";
        else { rank++; snprintf(vb, sizeof vb, "candidate#%d", rank); verdict = vb; }
        len += snprintf(g_wbuf + len, sizeof g_wbuf - len,
            "proc %d %ld %ld %c %s %s score=%ld age=%ld grow=%ld%s%s%s%s\n",
            p->pid, p->rss_kb, p->swap_kb, p->state, verdict, p->comm,
            s, p->age_s, p->growth_kb,
            (p->flags & PF_SESSION) ? " gui" : "",
            (p->flags & PF_TTY) ? " tty" : "",
            (p->flags & PF_SYSTEM_SVC) ? " svc" : "",
            (p->flags & PF_FROZEN) ? " frozen" : "");
        if (len >= (int)sizeof g_wbuf) len = (int)sizeof g_wbuf - 1;
    }
    if (g_lastkill[0])
        len += snprintf(g_wbuf + len, sizeof g_wbuf - len, "%s\n", g_lastkill);
    if (len >= (int)sizeof g_wbuf) len = (int)sizeof g_wbuf - 1;
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", g_state_path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, g_wbuf, (size_t)len);
    close(fd);
    /* Rename only a complete write: on tmpfs under memory shortage a write can
     * come up short, and the fragment would replace the last valid state. */
    if (w == (ssize_t)len) rename(tmp, g_state_path);
    else unlink(tmp);
}

/* pidfd of the last signalled victim: the next one waits until it exits or the grace ends */
static int g_pending_pidfd = -1;

/* Rate limits and escalation. Returns SIGTERM, SIGKILL or 0 for "not now". */
static int choose_signal(const proc_sample *p, const oom_verdict *v, long t) {
    long since = t - g_last_kill_ms;
    int repeat = p->pid == g_last_kill_pid && p->start_ticks == g_last_kill_start;
    if (g_last_kill_pid && since < g_rate_ms) return 0;
    if (g_dryrun && g_last_dry_ms && t - g_last_dry_ms < g_rate_ms) return 0;
    if (repeat && g_last_signal == SIGTERM && v->action != ACT_HARD && since < g_term_grace_ms) return 0;
    if (!repeat && g_pending_pidfd >= 0 && since < g_term_grace_ms) {
        struct pollfd pending = {.fd=g_pending_pidfd, .events=POLLIN};
        if (poll(&pending, 1, 0) <= 0) return 0; /* let the previous victim release its memory */
    }
    return v->action == ACT_HARD || (repeat && g_last_signal == SIGTERM && since >= g_term_grace_ms)
         ? SIGKILL : SIGTERM;
}

/* pidfd pins identity across the final check and the signal. No racy
 * kill(pid) fallback: a reused PID must never turn into a new victim.
 * Fills the current cgroup path and flags. Returns the pidfd or -1. */
static int pin_victim(const proc_sample *p, char *current, unsigned *current_flags) {
    int pidfd = (int)syscall(SYS_pidfd_open, p->pid, 0);
    if (pidfd < 0) { logline("aegis-oom: kill cancelled, pidfd_open unavailable or the process is gone"); return -1; }
    char path[64], statbuf[4096];
    snprintf(path, sizeof path, "/proc/%d/stat", p->pid);
    int tty = 0; unsigned long long start = 0;
    if (read_file(path, statbuf, sizeof statbuf) < 0 ||
        oom_parse_stat(statbuf, &tty, &start) != 0 || start != p->start_ticks ||
        aeg_pid_protected(p->pid, &g_pl)) {
        close(pidfd);
        logline("aegis-oom: kill cancelled, the process is gone, changed or protected");
        return -1;
    }
    char cgbuf[8192];
    snprintf(path, sizeof path, "/proc/%d/cgroup", p->pid);
    if (read_file(path, cgbuf, sizeof cgbuf) < 0) { close(pidfd); return -1; }
    *current_flags = oom_classify_cgroup(cgbuf, current, OOM_CGROUP_MAX);
    if (*current_flags & PF_FROZEN) {
        char freeze_path[512], frozen[32];
        snprintf(freeze_path, sizeof freeze_path, "/sys/fs/cgroup%s/cgroup.freeze", current);
        if ((*current_flags & PF_CG_TRUNC) || read_file(freeze_path, frozen, sizeof frozen) < 0 || atoi(frozen)) {
            close(pidfd); logline("aegis-oom: kill cancelled, the process is in a frozen cgroup"); return -1;
        }
    }
    return pidfd;
}

/* The whole leaf cgroup is a target only for SIGKILL, only when enabled, and
 * only if the victim is still in the cgroup it was scored in. */
static int open_cgroup_target(const proc_sample *p, int sig, const char *current, unsigned current_flags) {
    if (sig != SIGKILL || !g_cgroup_kill || (p->flags & PF_CG_TRUNC) || !oom_cgroup_killable(p->cgroup))
        return -1;
    if ((current_flags & PF_CG_TRUNC) || strcmp(current, p->cgroup)) return -1;
    char full[512]; snprintf(full, sizeof full, "/sys/fs/cgroup%s", p->cgroup);
    return aeg_guard_open(full, "/sys/fs/cgroup", &g_pl);
}

/* Consumes cgfd. Returns 1 if sent; *by_cgroup tells which way. */
static int send_kill(int pidfd, int cgfd, int sig, int *by_cgroup) {
    int sent = 0;
    *by_cgroup = 0;
    if (cgfd >= 0) {
        int fd = openat(cgfd, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) { sent = write(fd, "1", 1) == 1; close(fd); }
        close(cgfd);
        *by_cgroup = sent;
    }
    if (!sent) sent = syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0) == 0;
    return sent;
}

static void report_kill(const proc_sample *p, const oom_verdict *v, const mem_state *m, int sig, int by_cgroup) {
    snprintf(g_lastkill, sizeof g_lastkill,
        "lastkill %d %ld %s %s %s rss=%ldM swap=%ldM age=%lds grow=%ldM avail=%ldM psi_full=%.1f base=%.1f via=%s cg=%s",
        p->pid, p->rss_kb, sig == SIGKILL ? "SIGKILL" : "SIGTERM", reason_name(v->reason), p->comm,
        p->rss_kb / 1024, p->swap_kb / 1024, p->age_s, p->growth_kb / 1024,
        m->mem_avail_kb / 1024, m->psi_full_avg10, v->psi_baseline,
        by_cgroup ? "cgroup.kill" : "pidfd", p->cgroup[0] ? p->cgroup : "-");
    char message[700]; snprintf(message, sizeof message, "KILL: %s", g_lastkill + 9);
    logline(message);
}

static void act_kill(int vi, const oom_verdict *v, const mem_state *m) {
    if (vi < 0) return;
    proc_sample *p = &g_procs[vi];
    if (p->pid <= 1 || !p->start_ticks) return;
    long t = now_ms();
    int sig = choose_signal(p, v, t);
    if (!sig) return;
    char current[OOM_CGROUP_MAX]; unsigned current_flags = 0;
    int pidfd = pin_victim(p, current, &current_flags);
    if (pidfd < 0) return;
    int cgfd = open_cgroup_target(p, sig, current, current_flags);
    if (g_dryrun) {
        char message[256];
        snprintf(message, sizeof message, "DRYRUN would kill: %d %s %s rss=%ldM swap=%ldM via=%s",
                 p->pid, sig == SIGKILL ? "SIGKILL" : "SIGTERM", p->comm,
                 p->rss_kb / 1024, p->swap_kb / 1024, cgfd >= 0 ? "cgroup.kill" : "pidfd");
        logline(message);
        g_last_dry_ms = t;
        if (cgfd >= 0) close(cgfd);
        close(pidfd);
        return;
    }
    int by_cgroup;
    if (!send_kill(pidfd, cgfd, sig, &by_cgroup)) {
        close(pidfd); logline("aegis-oom: kill failed, the signal could not be sent"); return;
    }
    if (g_pending_pidfd >= 0) close(g_pending_pidfd);
    g_pending_pidfd = pidfd;
    g_last_kill_ms = t; g_last_kill_pid = p->pid;
    g_last_kill_start = p->start_ticks; g_last_signal = sig;
    report_kill(p, v, m, sig, by_cgroup);
}

static void apply_conf_kv(const char *key, const char *val) {
    if (!strcmp(key, "AEG_OOM_PROTECT")) {
        if (!g_cli_protect) oom_parse_protect(val, &g_pl);
        return;
    }
    if (!strcmp(key, "AEG_OOM_STATE")) {
        if (!g_cli_state && val[0] == '/' && strlen(val) < sizeof g_state_conf) {
            memcpy(g_state_conf, val, strlen(val) + 1); g_state_path = g_state_conf;
        }
        return;
    }
    struct { const char *key; void *dst; char type; double min, max; } map[] = {
        {"AEG_OOM_PSI_SOFT", &g_th.psi_soft, 'd', 0.1, 100},
        {"AEG_OOM_PSI_HARD", &g_th.psi_hard, 'd', 0.1, 100},
        {"AEG_OOM_BASELINE_K", &g_th.baseline_k, 'd', 1, 100},
        {"AEG_OOM_AVAIL_SOFT_PCT", &g_th.avail_soft_pct, 'd', 0, 90},
        {"AEG_OOM_AVAIL_HARD_PCT", &g_th.avail_hard_pct, 'd', 0, 90},
        {"AEG_OOM_SUSTAIN_N", &g_th.sustain_n, 'i', 1, 120},
        {"AEG_OOM_PROTECT_SMART", &g_th.protect_smart, 'i', 0, 1},
        {"AEG_OOM_CGROUP_KILL", &g_cgroup_kill, 'i', 0, 1},
        {"AEG_OOM_DRYRUN", &g_dryrun, 'i', 0, 1},
        {"AEG_OOM_RATE_MS", &g_rate_ms, 'l', 100, 60000},
        {"AEG_OOM_REFRESH_MS", &g_refresh_ms, 'i', 100, 60000},
        {"AEG_OOM_IDLE_MS", &g_idle_ms, 'i', 100, 60000},
        {"AEG_OOM_IDLE_SCAN_S", &g_idle_scan_s, 'i', 1, 3600},
        {"AEG_OOM_BASELINE_ALPHA", &g_baseline_alpha, 'd', 0.0001, 1},
        {"AEG_OOM_TERM_GRACE_MS", &g_term_grace_ms, 'l', 1000, 60000},
        {"AEG_OOM_PSI_STALL_US", &g_psi_stall_us, 'l', 1, 10000000},
        {"AEG_OOM_PSI_WINDOW_US", &g_psi_window_us, 'l', 500000, 10000000},
        {"AEG_OOM_AVAIL_SOFT_MB", &g_th.avail_soft_kb, 'm', 1, 1048576},
        {"AEG_OOM_AVAIL_HARD_MB", &g_th.avail_hard_kb, 'm', 1, 1048576},
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (strcmp(key, map[i].key)) continue;
        if (!strcmp(key, "AEG_OOM_DRYRUN") && g_cli_dryrun) return;
        double value;
        if (!aeg_config_number(val, map[i].min, map[i].max, map[i].type != 'd', &value)) {
            logline("aegis-oom: invalid numeric config value ignored");
            return;
        }
        if (map[i].type == 'd') *(double *)map[i].dst = value;
        else if (map[i].type == 'i') *(int *)map[i].dst = (int)value;
        else *(long *)map[i].dst = (long)value * (map[i].type == 'm' ? 1024 : 1);
        if (map[i].dst == &g_th.avail_soft_kb) g_th.avail_soft_pct = 0;
        if (map[i].dst == &g_th.avail_hard_kb) g_th.avail_hard_pct = 0;
        return;
    }
}

static void apply_conf_line(const char *line) {
    char key[80], val[1024];
    if (aeg_config_assignment(line, key, sizeof key, val, sizeof val)) apply_conf_kv(key, val);
}

static void load_conf(const char *path) {
    if (read_file(path, g_rbuf, sizeof g_rbuf) < 0) return;
    aeg_config_each(g_rbuf, apply_conf_kv);
}

static int run_once(void) {
    int n = scan_all();
    mem_state m; read_mem_state(&m);
    thresholds th = cycle_thresholds(&m);
    oom_verdict v = oom_decide_v2(&m, &th, g_baseline, g_sustain);
    /* a forced kill must not look like a threshold trigger in the journal */
    if (g_force != ACT_NONE) { v.action = g_force; v.reason = RS_FORCED; }
    int vi = select_victim(n);
    if (vi >= 0) {
        printf("victim pid=%d comm=%s rss_kb=%ld score=%ld action=%s reason=%s\n",
            g_procs[vi].pid, g_procs[vi].comm, g_procs[vi].rss_kb,
            oom_victim_score(&g_procs[vi], &g_pl, &g_th), action_name(v.action), reason_name(v.reason));
    } else {
        printf("victim none action=%s reason=%s\n", action_name(v.action), reason_name(v.reason));
    }
    if (v.action >= ACT_SOFT) act_kill(vi, &v, &m);
    write_state(n, &m, &v, 0);
    return 0;
}

static void ensure_rundir(void) {
    mkdir("/run/aegis", 0755);
    /* the watch file is world writable: a monitor runs as a user and the
     * directory belongs to root */
    int fd = open(g_watch_path, O_WRONLY | O_CREAT, 0666);
    if (fd >= 0) { fchmod(fd, 0666); close(fd); }
}

/* The learned baseline survives a reboot: otherwise the killer spends five
 * minutes relearning what PSI is normal for this machine. */
static void learn_load(void) {
    if (!g_learning) return;
    char b[256];
    if (read_file(g_learn_path, b, sizeof b) <= 0) return;
    g_baseline = atof(b);
}

static void learn_save(void) {
    if (!g_learning) return;
    mkdir("/var/lib/aegis", 0755);
    char tmp[256], buf[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_learn_path);
    int n = snprintf(buf, sizeof buf, "%.4f\n", g_baseline);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
    close(fd);
    rename(tmp, g_learn_path);
}

/* A monitor touches the watch file while it looks. A fresh mtime keeps the hot
 * cycle with scans; otherwise scanning /proc while idle is pointless. */
static int watcher_active(void) {
    struct stat st;
    if (stat(g_watch_path, &st) != 0) return 0;
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return 0;
    long age = (long)(now.tv_sec - st.st_mtim.tv_sec);
    return age >= 0 && age <= 3;
}

static void load_env(void) {
    g_th.psi_soft       = env_d("AEG_OOM_PSI_SOFT", 20.0);
    g_th.psi_hard       = env_d("AEG_OOM_PSI_HARD", 40.0);
    g_th.avail_soft_kb  = env_l("AEG_OOM_AVAIL_SOFT_MB", 0) * 1024;
    g_th.avail_hard_kb  = env_l("AEG_OOM_AVAIL_HARD_MB", 0) * 1024;
    g_th.avail_soft_pct = env_d("AEG_OOM_AVAIL_SOFT_PCT", g_th.avail_soft_kb ? 0.0 : 4.0);
    g_th.avail_hard_pct = env_d("AEG_OOM_AVAIL_HARD_PCT", g_th.avail_hard_kb ? 0.0 : 1.5);
    g_th.baseline_k     = env_d("AEG_OOM_BASELINE_K", 2.0);
    g_th.sustain_n      = (int)env_l("AEG_OOM_SUSTAIN_N", 3);
    g_th.protect_smart  = (int)env_l("AEG_OOM_PROTECT_SMART", 1);
    g_cgroup_kill       = (int)env_l("AEG_OOM_CGROUP_KILL", 0);
    g_rate_ms           = env_l("AEG_OOM_RATE_MS", 2000);
    g_term_grace_ms     = env_l("AEG_OOM_TERM_GRACE_MS", 8000);
    g_dryrun            = (int)env_l("AEG_OOM_DRYRUN", 1);
    g_refresh_ms        = (int)env_l("AEG_OOM_REFRESH_MS", 1500);
    const char *wp      = getenv("AEG_OOM_WATCH"); if (wp && *wp) g_watch_path = wp;
    g_idle_ms           = (int)env_l("AEG_OOM_IDLE_MS", 6000);
    g_idle_scan_s       = (int)env_l("AEG_OOM_IDLE_SCAN_S", 60);
    if (g_idle_ms < g_refresh_ms) g_idle_ms = g_refresh_ms;
    g_psi_stall_us      = env_l("AEG_OOM_PSI_STALL_US", 150000);
    g_psi_window_us     = env_l("AEG_OOM_PSI_WINDOW_US", 1000000);
    g_baseline_alpha    = env_d("AEG_OOM_BASELINE_ALPHA", 0.02);
    const char *st      = getenv("AEG_OOM_STATE"); if (st) g_state_path = st;
    const char *cf      = getenv("AEG_OOM_CONF");  if (cf) g_conf_path = cf;
    const char *pp      = getenv("AEG_OOM_PSI_PATH"); if (pp) g_psi_path = pp;
    const char *env_prot = getenv("AEG_OOM_PROTECT");
    if (env_prot) { char line[2048]; snprintf(line, sizeof line, "AEG_OOM_PROTECT=%s", env_prot); apply_conf_line(line); }
}

/* Precedence: defaults, environment, config file, flags. The file is read
 * before the flags so that it never overrides an explicit --protect or --dry-run. */
static void load_conf_before_flags(int argc, char **argv) {
    int pre_conf = 1;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--conf") && i + 1 < argc) g_conf_path = argv[++i];
        else if (!strcmp(argv[i], "--no-conf")) pre_conf = 0;
    if (pre_conf) load_conf(g_conf_path);
}

/* returns 0 on success, 2 on a usage error */
static int parse_args(int argc, char **argv, int *once) {
    const char *prot = NULL;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--once"))    *once = 1;
        else if (!strcmp(argv[i], "--dry-run")) { g_dryrun = 1; g_cli_dryrun = 1; }
        else if (!strcmp(argv[i], "--live"))    { g_dryrun = 0; g_cli_dryrun = 1; }
        else if (!strcmp(argv[i], "--no-arm"))  g_arm = 0;
        else if (!strcmp(argv[i], "--scope") && i + 1 < argc) g_scope = argv[++i];
        else if (!strcmp(argv[i], "--protect") && i + 1 < argc) { prot = argv[++i]; g_cli_protect = 1; }
        else if (!strcmp(argv[i], "--state") && i + 1 < argc) { g_state_path = argv[++i]; g_cli_state = 1; }
        else if (!strcmp(argv[i], "--conf") && i + 1 < argc) g_conf_path = argv[++i];
        else if (!strcmp(argv[i], "--no-conf")) g_no_conf = 1;
        else if (!strcmp(argv[i], "--no-learn")) g_learning = 0;
        else if (!strcmp(argv[i], "--force") && i + 1 < argc) {
            const char *f = argv[++i];
            g_force = !strcmp(f, "hard") ? ACT_HARD : !strcmp(f, "soft") ? ACT_SOFT : ACT_NONE;
            if (g_force == ACT_NONE) { logline("aegis-oom: --force expects soft or hard"); return 2; }
        }
        else { logline("aegis-oom: unknown argument or missing value"); return 2; }
    }
    /* the protect list stays as a manual override on top of smart protection */
    if (prot) oom_parse_protect(prot, &g_pl);
    if (g_force != ACT_NONE && (!*once || !g_scope)) { logline("aegis-oom: --force requires --once and a separate --scope"); return 2; }
    return 0;
}

/* PSI trigger on the root cgroup memory.pressure. Without it the loop polls on a timeout.
 * Returns the epoll fd, or -1; *pfd is the PSI fd or -1. */
static int open_wakeup(int *pfd, int *have_trigger) {
    *pfd = open(g_psi_path, O_RDWR | O_CLOEXEC);
    *have_trigger = 0;
    if (*pfd >= 0) {
        char trig[64];
        int tl = snprintf(trig, sizeof trig, "some %ld %ld", g_psi_stall_us, g_psi_window_us);
        if (write(*pfd, trig, (size_t)tl) == tl) *have_trigger = 1;
        else logline("aegis-oom: PSI trigger rejected, falling back to polling");
    } else {
        logline("aegis-oom: PSI unavailable, falling back to polling");
    }
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) { logline("aegis-oom: epoll_create1 failed"); return -1; }
    if (*have_trigger) {
        struct epoll_event ev = { .events = EPOLLPRI, .data.fd = *pfd };
        if (epoll_ctl(ep, EPOLL_CTL_ADD, *pfd, &ev) < 0) {
            *have_trigger = 0;
            logline("aegis-oom: epoll_ctl failed, falling back to polling");
        }
    }
    return ep;
}

static void log_armed(int have_trigger) {
    mem_state m0; read_mem_state(&m0); thresholds th = cycle_thresholds(&m0);
    char b[256]; snprintf(b, sizeof b,
        "aegis-oom armed (mode=%s wake=%s psi_soft=%.0f psi_hard=%.0f avail_soft=%ldMiB avail_hard=%ldMiB smart=%d sustain=%d cgroup_kill=%d)",
        g_dryrun ? "DRY" : "LIVE", have_trigger ? "PSI-trigger" : "poll",
        th.psi_soft, th.psi_hard, th.avail_soft_kb / 1024, th.avail_hard_kb / 1024,
        g_th.protect_smart, g_th.sustain_n, g_cgroup_kill);
    logline(b);
}

static void reload_conf(void) {
    if (!g_no_conf) load_conf(g_conf_path);
    validate_runtime_settings();
    char b[256]; snprintf(b, sizeof b,
        "aegis-oom: config reloaded psi_hard=%.0f soft_pct=%.1f hard_pct=%.1f sustain=%d smart=%d dryrun=%d",
        g_th.psi_hard, g_th.avail_soft_pct, g_th.avail_hard_pct,
        g_th.sustain_n, g_th.protect_smart, g_dryrun);
    logline(b);
}

static void run_loop(int ep) {
    unsigned cycle = 0;
    int wait_ms = g_refresh_ms;
    int n = 0;                       /* size of the last candidate snapshot */
    time_t last_scan = 0, last_learn = time(0);
    while (!g_stop) {
        struct epoll_event out;
        /* A PSI event wakes us at once; the timeout is the polling fallback for the avail threshold. */
        int woke = epoll_wait(ep, &out, 1, wait_ms);
        if (g_reload) { g_reload = 0; reload_conf(); }

        /* The cheap part: two files. They are enough to decide whether to kill. */
        mem_state m; read_mem_state(&m);
        thresholds th = cycle_thresholds(&m);

        /* Distance to the threshold sets the pace: far away sleeps long, close polls often. */
        int near = (m.mem_avail_kb >= 0 && th.avail_soft_kb > 0 &&
                    m.mem_avail_kb <= th.avail_soft_kb * 4) ||
                   m.psi_some_avg10 >= g_th.psi_soft / 2.0;
        int prev_wait = wait_ms;
        wait_ms = near ? g_refresh_ms : g_idle_ms;

        /* The EWMA assumed a fixed cycle; with a variable step the coefficient is
         * scaled, otherwise the baseline freezes while idle and jumps under load. */
        double a = g_baseline_alpha * ((double)prev_wait / (double)g_refresh_ms);
        if (a > 1.0) a = 1.0;
        g_baseline = oom_update_baseline(g_baseline, m.psi_full_avg10, a);

        oom_verdict v = oom_decide_v2(&m, &th, g_baseline, g_sustain);

        /* The /proc scan exists only to pick a victim. While idle it is cosmetic for
         * the monitor: run it only if a monitor is watching, PSI woke us,
         * or the snapshot is stale. */
        time_t now = time(0);
        int want_scan = (v.action >= ACT_SOFT) || near || woke > 0 ||
                        watcher_active() ||
                        (now - last_scan) >= g_idle_scan_s;
        if (want_scan) { n = scan_all(); inherit_protection(n); last_scan = now; }

        if (v.action >= ACT_SOFT) {
            int vi = select_victim(n);
            act_kill(vi, &v, &m);
            g_sustain++;
        } else {
            if (want_scan && (++cycle % 4) == 0) enrich_top(n);
            g_sustain = 0;
        }
        write_state(n, &m, &v, (int)(now - last_scan));
        if (now - last_learn >= 300) { learn_save(); last_learn = now; }
    }
}

int main(int argc, char **argv) {
    g_self_pid = (int)getpid();
    g_hz = sysconf(_SC_CLK_TCK); if (g_hz <= 0) g_hz = 100;

    load_env();
    load_conf_before_flags(argc, argv);
    int once = 0;
    int rc = parse_args(argc, argv, &once);
    if (rc) return rc;
    validate_runtime_settings();
    if (!once) ensure_rundir();
    learn_load();
    setup_signals();
    if (g_arm) arm("aegis-oom");

    if (once) return run_once();

    int pfd, have_trigger;
    int ep = open_wakeup(&pfd, &have_trigger);
    if (ep < 0) { if (pfd >= 0) close(pfd); return 1; }
    log_armed(have_trigger);
    run_loop(ep);
    learn_save();
    close(ep);
    if (pfd >= 0) close(pfd);
    return 0;
}
