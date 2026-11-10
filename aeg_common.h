#ifndef AEG_COMMON_H
#define AEG_COMMON_H
/* Helpers shared by aegis-oom and aegis-reaper. Header only, no heap allocation. */
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

struct ld64 { uint64_t d_ino, d_off; uint16_t d_reclen; uint8_t d_type; char d_name[]; };

static inline void logline(const char *s) {
    char b[1024];
    int n = snprintf(b, sizeof b, "%s\n", s);
    if (n < 0) return;
    if (n >= (int)sizeof b) { n = (int)sizeof b; b[n - 1] = '\n'; }
    /* stderr goes to the journal; a failed log write has no better place to be reported */
    ssize_t w = write(2, b, (size_t)n); (void)w;
}

/* Reads at most n-1 bytes and terminates them. Longer files are silently truncated. */
static inline int read_file(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t k = read(fd, buf, n - 1);
    close(fd);
    if (k < 0) return -1;
    buf[k] = 0; return (int)k;
}

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static void on_term(int s) { (void)s; g_stop = 1; }
static void on_hup(int s)  { (void)s; g_reload = 1; }

static inline void setup_signals(void) {
    signal(SIGTERM, on_term); signal(SIGINT, on_term); signal(SIGHUP, on_hup);
}

/* Hardening reports each failure: a daemon that is swapped out or starved of
 * CPU must not be counted as ready. */
static inline void arm(const char *who) {
    char b[160];
    int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, "-1000", 5) != 5) {
        snprintf(b, sizeof b, "%s: hardening failed, oom_score_adj not set; the kernel OOM killer may pick this daemon", who);
        logline(b);
    }
    if (fd >= 0) close(fd);
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        snprintf(b, sizeof b, "%s: hardening failed, mlockall refused; under pressure this daemon may be swapped out", who);
        logline(b);
    }
    struct sched_param sp; sp.sched_priority = 40;
    if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) {
        snprintf(b, sizeof b, "%s: hardening failed, SCHED_FIFO not set; under CPU saturation this daemon may not get time", who);
        logline(b);
    }
}
#endif
