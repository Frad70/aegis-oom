#define _GNU_SOURCE
#include "cgroup_guard.h"
#include <sys/prctl.h>
#include <sys/wait.h>

static int failures;
#define CHECK(c, message) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", message); failures++; } } while (0)

static void member_file(const char *root, const char *text) {
    char path[1024]; snprintf(path, sizeof path, "%s/job.scope/cgroup.procs", root);
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    fputs(text, f); fclose(f);
}

int main(void) {
    char root[] = "/tmp/aegis-guard-XXXXXX";
    CHECK(mkdtemp(root), "fixture directory");
    char path[1024], text[80];
    snprintf(path, sizeof path, "%s/job.scope", root); CHECK(!mkdir(path, 0700), "leaf fixture");
    snprintf(text, sizeof text, "%d\n", (int)getpid()); member_file(root, text);
    protect_list pl; oom_parse_protect("", &pl);
    int fd = aeg_guard_open(path, root, &pl);
    CHECK(fd >= 0, "valid complete membership accepted"); if (fd >= 0) close(fd);
    CHECK(aeg_guard_open(root, root, &pl) < 0, "root is never a victim");
    aeg_guard_init();
    CHECK(aeg_guard_open(path, root, &pl) < 0, "a leaf holding the daemon itself is refused");
    memset(g_guard_pids, 0, sizeof g_guard_pids);
    char bad[1200]; snprintf(bad, sizeof bad, "%s/../%s/job.scope", root, strrchr(root, '/') + 1);
    CHECK(aeg_guard_open(bad, root, &pl) < 0, "parent traversal rejected");
    snprintf(bad, sizeof bad, "%s/alias", root); CHECK(!symlink(path, bad), "symlink fixture");
    CHECK(aeg_guard_open(bad, root, &pl) < 0, "symlink traversal rejected"); unlink(bad);
    snprintf(bad, sizeof bad, "%s/child", path); mkdir(bad, 0700);
    CHECK(aeg_guard_open(path, root, &pl) < 0, "ancestor with children is never a leaf"); rmdir(bad);
    member_file(root, "123invalid\n"); CHECK(aeg_guard_open(path, root, &pl) < 0, "malformed PID list rejected");
    member_file(root, ""); CHECK(aeg_guard_open(path, root, &pl) < 0, "empty membership rejected");
    member_file(root, "21474836480\n"); CHECK(aeg_guard_open(path, root, &pl) < 0, "PID overflow rejected");

    prctl(PR_SET_NAME, "guard-parent", 0, 0, 0);
    int pipes[2]; CHECK(!pipe(pipes), "pipe");
    pid_t child = fork();
    if (child == 0) {
        close(pipes[1]); prctl(PR_SET_NAME, "guard-worker", 0, 0, 0);
        char c; _exit(read(pipes[0], &c, 1) < 0);
    }
    CHECK(child > 0, "child fixture"); close(pipes[0]);
    if (child > 0) {
        snprintf(text, sizeof text, "%d\n", (int)child); member_file(root, text);
        oom_parse_protect("guard-parent", &pl);
        CHECK(aeg_guard_open(path, root, &pl) < 0, "protected parent protects differently named child");
        oom_parse_protect("", &pl);
        fd = aeg_guard_open(path, root, &pl);
        CHECK(fd >= 0, "unprotected child accepted"); if (fd >= 0) close(fd);
        close(pipes[1]); waitpid(child, NULL, 0);
    } else close(pipes[1]);
    snprintf(bad, sizeof bad, "%s/cgroup.procs", path); unlink(bad); rmdir(path); rmdir(root);
    if (failures) return 1;
    puts("OK: cgroup guard"); return 0;
}
