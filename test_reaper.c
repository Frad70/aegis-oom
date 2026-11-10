/* Exercise the reaper configuration without starting the daemon. */
#define main reaper_main
#include "reaper.c"
#undef main

static int failures;
#define EXPECT(c, message) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", message); failures++; } } while (0)

static char conf_path[] = "/tmp/aegis-reaper-conf-XXXXXX";

static void write_conf(const char *text) {
    FILE *f = fopen(conf_path, "w");
    if (!f) { perror(conf_path); exit(1); }
    fputs(text, f); fclose(f);
}

static void config(void) {
    int fd = mkstemp(conf_path);
    EXPECT(fd >= 0, "config fixture"); if (fd < 0) return;
    close(fd);
    setenv("AEG_CONF", conf_path, 1);
    unsetenv("AEG_REAPER_PROTECT"); unsetenv("AEG_REAPER_DRYRUN");

    write_conf("AEG_OOM_PROTECT=\nAEG_REAPER_DRYRUN=0\n");
    load_protection();
    EXPECT(oom_is_protected("sshd", &protection), "empty protect value keeps the built-in list");
    EXPECT(!dryrun, "dry run off");

    write_conf("AEG_OOM_PROTECT=java,firefox # comment\nAEG_REAPER_DRYRUN=1\n");
    load_protection();
    EXPECT(oom_is_protected("firefox", &protection) && !oom_is_protected("sshd", &protection),
           "a protect value replaces the built-in list");
    EXPECT(dryrun, "dry run on");

    write_conf("AEG_REAPER_DRYRUN=maybe\n");
    load_protection();
    EXPECT(dryrun, "an invalid dry run value fails safe");

    setenv("AEG_REAPER_PROTECT", "steamwebhelper", 1);
    write_conf("");
    load_protection();
    EXPECT(oom_is_protected("steamwebhelper", &protection), "environment override applies");
    unsetenv("AEG_REAPER_PROTECT");
    unlink(conf_path);
}

static void checked_numbers(void) {
    long v = 0;
    EXPECT(aeg_parse_long("8000", 1, INT_MAX, &v) && v == 8000, "plain number");
    EXPECT(aeg_parse_long("-1000\n", -1000, 1000, &v) && v == -1000, "kernel file with newline");
    EXPECT(!aeg_parse_long("12x", 1, INT_MAX, &v), "trailing garbage rejected");
    EXPECT(!aeg_parse_long("", 1, INT_MAX, &v), "empty rejected");
    EXPECT(!aeg_parse_long("0", 1, INT_MAX, &v), "below range rejected");
    EXPECT(!aeg_parse_long("99999999999999999999", 1, INT_MAX, &v), "overflow rejected");
    EXPECT(!aeg_parse_long("2147483648", 1, INT_MAX, &v), "above int range rejected");
}

int main(void) {
    checked_numbers();
    config();
    if (failures) return 1;
    puts("OK: reaper");
    return 0;
}
