/* aegis-reaper: pre-armed fork bomb killer.
 *
 * While a fork bomb is active nothing new can fork and often nothing can
 * allocate memory. Only a process that is already running, locked in RAM,
 * with RT priority and immune to the OOM killer can help. It polls
 * pids.current of the watched cgroup; above the threshold it finds the leaf
 * cgroup with the most tasks and writes "1" to its cgroup.kill. No fork and
 * no heap allocation on the hot path.
 *
 * This is a safety net. A pids.max (TasksMax) limit on user slices keeps a bomb
 * from growing at all; the reaper covers a missing or bypassed limit.
 */
#define _GNU_SOURCE
#include "cgroup_guard.h"
#include "config_value.h"
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>

#define USER_SLICE "/sys/fs/cgroup/user.slice"
#define PATHMAX    1024
#define DBUF       (64*1024)

static const char *user_slice = USER_SLICE;
static long  threshold   = 10000;             /* tasks in the watched cgroup that trigger a scan */
static long  leaf_min    = 300;               /* never kill a leaf smaller than this */
static long  interval_ns = 250L*1000L*1000L;  /* 250 ms while idle */
static const char *target_file = "/run/aegis/reaper_target";

/* static buffers: no allocations at runtime */
static char best_path[PATHMAX];
static long best_pids;
static protect_list protection;
static int dryrun;
static volatile sig_atomic_t reload_config;
static void on_hup(int sig) { (void)sig; reload_config = 1; }

struct ld64 { /* linux_dirent64 */
    uint64_t d_ino, d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

/* libc snprintf/vsnprintf do not allocate heap memory: safe on the hot path */
static int snprintf_safe(char *d, size_t n, const char *f, ...) {
    va_list ap; va_start(ap, f);
    int r = vsnprintf(d, n, f, ap);
    va_end(ap);
    if (r < 0) r = 0;
    if ((size_t)r >= n) r = n ? (int)n - 1 : 0;
    return r;
}

static void logline(const char *s) { write(2, s, strlen(s)); write(2, "\n", 1); }

static void logkv(const char *msg, const char *path, long n) {
    char b[PATHMAX + 128]; int i = 0;
    i += snprintf_safe(b + i, sizeof b - i, "%s", msg);
    if (path) i += snprintf_safe(b + i, sizeof b - i, " %s", path);
    snprintf_safe(b + i, sizeof b - i, " pids=%ld", n);
    logline(b);
}

/* read an integer from <dir>/<name>; -1 if missing or empty */
static long read_long_at(const char *dir, const char *name) {
    char p[PATHMAX], buf[64];
    snprintf_safe(p, sizeof p, "%s/%s", dir, name);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t k = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (k <= 0) return -1;
    buf[k] = 0;
    long v = 0; const char *c = buf;
    while (*c >= '0' && *c <= '9') { v = v * 10 + (*c - '0'); c++; }
    return v;
}

/* recursive walk: find the leaf cgroup with the highest pids.current.
 * path is one shared mutable buffer of length plen; restored after recursion. */
static void scan(char *path, size_t plen, int depth) {
    if (depth > 32) return;
    char dbuf[DBUF];                 /* per recursion level, so a child walk does not clobber the
                                        parent's; on the stack because the cgroup tree is shallow */
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    int has_child = 0;
    for (;;) {
        long n = syscall(SYS_getdents64, fd, dbuf, sizeof dbuf);
        if (n <= 0) break;
        for (long off = 0; off < n; ) {
            struct ld64 *e = (struct ld64 *)(dbuf + off);
            off += e->d_reclen;
            if (e->d_type != DT_DIR) continue;
            const char *nm = e->d_name;
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
            has_child = 1;
            size_t nl = strlen(nm);
            if (plen + 1 + nl + 1 >= PATHMAX) continue;
            path[plen] = '/';
            memcpy(path + plen + 1, nm, nl + 1);
            scan(path, plen + 1 + nl, depth + 1);
            path[plen] = 0; /* restore the path; the parent's local dbuf survives recursion */
        }
    }
    close(fd);
    if (!has_child && depth > 0) {          /* a real leaf */
        long p = read_long_at(path, "pids.current");
        int guard = p > best_pids && p >= leaf_min ? aeg_guard_open(path, user_slice, &protection) : -1;
        if (guard >= 0) {
            close(guard);
            best_pids = p;
            strncpy(best_path, path, PATHMAX - 1);
            best_path[PATHMAX - 1] = 0;
        }
    }
}

/* kill a cgroup through cgroup.kill: one atomic kernel syscall */
static int kill_cgroup(const char *path) {
    if (dryrun) { logkv("DRYRUN reaper", path, 0); return -1; }
    return aeg_guard_kill(path, user_slice, &protection);
}

static void load_protection(void) {
    oom_parse_protect("systemd,sshd,dbus-daemon,dbus-broker,pipewire,wireplumber,Xorg,"
                      "gnome-shell,kwin_wayland,sway,weston", &protection);
    int global_dry = 0, reaper_dry = 0;
    const char *conf = getenv("AEG_CONF");
    char buf[64*1024];
    if (aeg_guard_read(conf ? conf : "/etc/aegis/aegis-oom.conf", buf, sizeof buf) >= 0) {
        char *line = buf;
        while (line && *line) {
            char *next = strchr(line, '\n'); if (next) *next++ = 0;
            char key[80], val[1024];
            if (aeg_config_assignment(line, key, sizeof key, val, sizeof val)) {
                if (!strcmp(key, "AEG_OOM_PROTECT")) oom_parse_protect(val, &protection);
                else if (!strcmp(key, "AEG_DRYRUN")) global_dry = strcmp(val, "0") != 0;
                else if (!strcmp(key, "AEG_REAPER_DRYRUN")) reaper_dry = strcmp(val, "0") != 0;
            }
            line = next;
        }
    }
    const char *override = getenv("AEG_REAPER_PROTECT");
    if (override) oom_parse_protect(override, &protection);
    override = getenv("AEG_REAPER_DRYRUN");
    if (override) reaper_dry = strcmp(override, "0") != 0;
    dryrun = global_dry || reaper_dry;
}

/* arm: unkillable + resident + prioritized */
static void arm(void) {
    int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, "-1000", 5) != 5) logline("reaper: oom_score_adj failed");
    if (fd >= 0) close(fd);
    if (mlockall(MCL_CURRENT | MCL_FUTURE)) logline("reaper: mlockall failed");
    struct sched_param sp; sp.sched_priority = 40;
    if (sched_setscheduler(0, SCHED_FIFO, &sp)) logline("reaper: SCHED_FIFO failed");
}

/* external escalation: a cgroup path written to the target file is killed, then the file is removed */
static void check_target_file(void) {
    int fd = open(target_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[PATHMAX];
    ssize_t k = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (k > 0) {
        if (buf[k - 1] == '\n') k--;
        buf[k] = 0;
        if (k > 0 && kill_cgroup(buf) == 0) logkv("reaper: killed escalated cgroup", buf, 0);
    }
    unlink(target_file);
}

int main(int argc, char **argv) {
    if (argc > 1) threshold = atol(argv[1]);
    if (argc > 2) user_slice = argv[2];
    if (argc > 3) leaf_min = atol(argv[3]);
    if (threshold < 1 || leaf_min < 1 || user_slice[0] != '/') return 2;
    load_protection();
    signal(SIGHUP, on_hup);
    arm();
    logkv("aegis-reaper armed (mlock+RT+oom-1000), threshold on", user_slice, threshold);

    struct timespec ts;
    char path[PATHMAX];
    for (;;) {
        if (reload_config) { reload_config = 0; load_protection(); }
        check_target_file();
        long total = read_long_at(user_slice, "pids.current");
        if (total >= threshold) {
            best_pids = 0; best_path[0] = 0;
            size_t l = strlen(user_slice);
            if (l < PATHMAX) {
                memcpy(path, user_slice, l + 1);
                scan(path, l, 0);
            }
            if (best_path[0] && best_pids >= leaf_min) {
                if (kill_cgroup(best_path) == 0)
                    logkv("reaper: killed fork bomb cgroup", best_path, best_pids);
                else
                    logkv("reaper: cgroup.kill failed for", best_path, best_pids);
            } else {
                logkv("reaper: threshold exceeded, no single leaf to kill in", user_slice, total);
            }
            ts.tv_sec = 0; ts.tv_nsec = 50L * 1000L * 1000L; /* hot: poll more often */
        } else {
            ts.tv_sec = 0; ts.tv_nsec = interval_ns;
        }
        nanosleep(&ts, 0);
    }
    return 0;
}
