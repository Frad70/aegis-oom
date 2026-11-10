#ifndef AEG_CGROUP_GUARD_H
#define AEG_CGROUP_GUARD_H
/* Shared by aegis-oom and aegis-reaper. No fork, heap allocation or shell commands. */
#include "oom_policy.h"
#include "aeg_common.h"
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static inline int aeg_guard_read(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    ssize_t n;
    do { n = read(fd, buf, size - 1); } while (n < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (n < 0 || n == (ssize_t)size - 1) { errno = n < 0 ? saved : EOVERFLOW; return -1; }
    buf[n] = 0;
    return (int)n;
}

/* A protected application includes its descendants, regardless of comm. */
static inline int aeg_pid_protected(int pid, const protect_list *pl) {
    for (int depth = 0; depth < 64; depth++) {   /* same bound as the scan in aegis-oom */
        if (pid <= 1) return depth == 0;
        char path[64], buf[8192];
        snprintf(path, sizeof path, "/proc/%d/status", pid);
        if (aeg_guard_read(path, buf, sizeof buf) < 0) return errno == ENOENT ? 0 : 1;
        proc_sample p = {0};
        oom_parse_status(buf, &p);
        if (!p.comm[0]) return 1;
        if (depth > 0 && oom_ancestry_boundary(p.comm)) return 0;
        if (pl && oom_is_protected(p.comm, pl)) return 1;
        snprintf(path, sizeof path, "/proc/%d/oom_score_adj", pid);
        if (aeg_guard_read(path, buf, sizeof buf) < 0) return errno == ENOENT ? 0 : 1;
        if (atoi(buf) <= OOM_ADJ_IMMUNE) return 1;
        if (p.ppid == pid || p.ppid < 0) return 1;
        pid = p.ppid;
    }
    return 1; /* incomplete ancestry is not permission to kill */
}

static inline int aeg_guard_members(int dirfd, const protect_list *pl) {
    int fd = openat(dirfd, "cgroup.procs", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;
    char buf[4096];
    long pid = 0;
    int digits = 0, members = 0, ok = 1;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = 0; break; }
        if (!n) { if (digits) { members++; if (aeg_pid_protected((int)pid, pl)) ok = 0; } break; }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] >= '0' && buf[i] <= '9') {
                int digit = buf[i] - '0';
                if (pid > (INT_MAX - digit) / 10) { ok = 0; break; }
                pid = pid * 10 + digit; digits = 1;
            } else if (buf[i] == '\n') {
                if (!digits || pid <= 1 || aeg_pid_protected((int)pid, pl)) { ok = 0; break; }
                members++; pid = 0; digits = 0;
            } else { ok = 0; break; }
        }
        if (!ok) break;
    }
    close(fd);
    return ok && members > 0;
}

static inline int aeg_guard_leaf(int dirfd) {
    int scanfd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scanfd < 0) return 0;
    char buf[4096];
    int leaf = 1;
    for (;;) {
        long n = syscall(SYS_getdents64, scanfd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { leaf = 0; break; }
        if (!n) break;
        for (long off = 0; off < n;) {
            struct ld64 *e = (void *)(buf + off);
            if (!e->d_reclen || off + e->d_reclen > n) { leaf = 0; break; }
            off += e->d_reclen;
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            struct stat st;
            if (fstatat(scanfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode)) {
                leaf = 0; break;
            }
        }
        if (!leaf) break;
    }
    close(scanfd);
    return leaf;
}

/* Pin the directory and walk every component without following symlinks.
 * Never target a shared login session, slice, subtree or the allowed root. */
static inline int aeg_guard_open(const char *path, const char *root, const protect_list *pl) {
    size_t rn = strlen(root);
    if (!rn || root[0] != '/' || strncmp(path, root, rn) || path[rn] != '/' || !path[rn+1]) return -1;
    const char *last = strrchr(path, '/') + 1;
    size_t ln = strlen(last);
    if ((ln >= 6 && !strcmp(last + ln - 6, ".slice")) ||
        (!strncmp(last, "session-", 8) && ln >= 6 && !strcmp(last + ln - 6, ".scope")) ||
        !strcmp(last, "aegis.service") || !strcmp(last, "aegis-oom.service") || !strcmp(last, "aegis-reaper.service")) return -1;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    const char *s = path + rn + 1;
    while (*s) {
        const char *slash = strchr(s, '/');
        size_t n = slash ? (size_t)(slash - s) : strlen(s);
        if (!n || n > 255 || (n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.')) { close(fd); return -1; }
        char component[256]; memcpy(component, s, n); component[n] = 0;
        int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(fd);
        if (next < 0) return -1;
        fd = next;
        if (!slash) break;
        s = slash + 1;
        if (!*s) { close(fd); return -1; }
    }
    if (!aeg_guard_leaf(fd) || !aeg_guard_members(fd, pl)) { close(fd); return -1; }
    return fd;
}

static inline int aeg_guard_kill(const char *path, const char *root, const protect_list *pl) {
    int dfd = aeg_guard_open(path, root, pl);
    if (dfd < 0) return -1;
    int fd = openat(dfd, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int ok = fd >= 0 && write(fd, "1", 1) == 1;
    if (fd >= 0) close(fd);
    close(dfd);
    return ok ? 0 : -1;
}
#endif
