#include "oom_policy.h"
#include <string.h>
#include <stdlib.h>

/* victim score weights */
#define SWAP_WEIGHT      0.25   /* swapped memory frees only a fraction of RAM */
#define GROWTH_WEIGHT    2.0    /* growth since the last sample: the likely cause */
#define GUI_FACTOR       0.15   /* holds a GPU node: an app of the live session */
#define SERVICE_FACTOR   0.60   /* system.slice */
#define AGE_DAY_FACTOR   0.35   /* running longer than a day */
#define AGE_HOUR_FACTOR  0.60   /* running longer than an hour */
#define FRESH_FACTOR     1.25   /* started less than a minute ago; also the bound before enrichment */
#define AGE_DAY_S        86400
#define AGE_HOUR_S       3600
#define AGE_FRESH_S      60
#define ADJ_FACTOR_MIN   0.001

/* clamp rails for thresholds computed from percentages */
#define AVAIL_HARD_MIN_KB (128L*1024)
#define AVAIL_HARD_MAX_KB (1024L*1024)
#define AVAIL_SOFT_MIN_KB (384L*1024)
#define AVAIL_SOFT_MAX_KB (3072L*1024)

/* All parsers expect a NUL-terminated buf (the caller always terminates it via read_file). */

int oom_parse_protect(const char *csv, protect_list *pl) {
    pl->count = 0;
    if (!csv) return 0;
    const char *p = csv;
    while (*p && pl->count < OOM_MAX_PROTECT) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t')) len--;
        if (len > 0) {
            if (len >= OOM_COMM_MAX) len = OOM_COMM_MAX - 1;
            memcpy(pl->names[pl->count], start, len);
            pl->names[pl->count][len] = 0;
            pl->count++;
        }
    }
    return pl->count;
}

int oom_is_protected(const char *comm, const protect_list *pl) {
    for (int i = 0; i < pl->count; i++)
        if (strcmp(comm, pl->names[i]) == 0) return 1;
    return 0;
}

int oom_ancestry_boundary(const char *comm) {
    static const char *const names[] = {"systemd", "sshd", "login", "bash", "zsh", "sh", "dash", "fish",
                                       "Xorg", "gnome-shell", "kwin_wayland", "sway", "weston",
                                       "kitty", "foot", "alacritty", "xterm", "konsole",
                                       "gnome-terminal-", "tmux: server"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++)
        if (!strcmp(comm, names[i])) return 1;
    return 0;
}

long oom_victim_score(const proc_sample *p, const protect_list *pl, const thresholds *t) {
    if (p->pid <= 1) return -1;
    if (p->rss_kb <= 0) return -1;                 /* kthread/zombie: nothing to kill */
    if (p->oom_score_adj <= OOM_ADJ_IMMUNE) return -1;
    if (p->flags & (PF_SELF | PF_PROTECTED_TREE | PF_FROZEN)) return -1;
    if (pl && oom_is_protected(p->comm, pl)) return -1;

    /* Resident relief comes first. Disk swap is already outside RAM; even
     * compressed swap occupies only a fraction of its logical size. Bound
     * its contribution so a mostly swapped idle app is not the scapegoat. */
    long swap = p->swap_kb > 0 ? p->swap_kb : 0;
    if (swap > p->rss_kb) swap = p->rss_kb;
    double base = (double)p->rss_kb + (double)swap * SWAP_WEIGHT;
    /* a growing process is the likely cause of pressure, not a large bystander */
    if (p->growth_kb > 0) base += (double)p->growth_kb * GROWTH_WEIGHT;

    if (t && t->protect_smart && (p->flags & PF_ENRICHED)) {
        if (p->flags & PF_SESSION)    base *= GUI_FACTOR;
        if (p->flags & PF_SYSTEM_SVC) base *= SERVICE_FACTOR;
        if (p->age_s > AGE_DAY_S)     base *= AGE_DAY_FACTOR;
        else if (p->age_s > AGE_HOUR_S) base *= AGE_HOUR_FACTOR;
        else if (p->age_s >= 0 && p->age_s < AGE_FRESH_S) base *= FRESH_FACTOR;
    } else if (t && t->protect_smart) {
        /* Upper bound until enrichment. A lower bound would hide a genuine
         * candidate below discounted GUI processes. */
        base *= FRESH_FACTOR;
    }
    /* the kernel hint is a multiplier, not an addend: a 35 MB helper with adj=+300
     * must not outrank a process ten times larger. */
    double k = 1.0 + (double)p->oom_score_adj / OOM_ADJ_SCALE;
    if (k < ADJ_FACTOR_MIN) k = ADJ_FACTOR_MIN;
    double score = base * k;
    if (score < 1) score = 1;
    return (long)score;
}

int oom_pick_victim(const proc_sample *procs, int n, const protect_list *pl, const thresholds *t) {
    int best = -1; long best_score = 0;
    for (int i = 0; i < n; i++) {
        long s = oom_victim_score(&procs[i], pl, t);
        if (s > best_score) { best_score = s; best = i; }
    }
    return best;
}

static long clampl(long v, long lo, long hi) { return v < lo ? lo : (v > hi ? hi : v); }

void oom_resolve_thresholds(const mem_state *m, thresholds *t) {
    if (m->mem_total_kb > 0) {
        if (t->avail_hard_pct > 0)
            t->avail_hard_kb = clampl((long)(m->mem_total_kb * t->avail_hard_pct / 100.0),
                                      AVAIL_HARD_MIN_KB, AVAIL_HARD_MAX_KB);
        if (t->avail_soft_pct > 0)
            t->avail_soft_kb = clampl((long)(m->mem_total_kb * t->avail_soft_pct / 100.0),
                                      AVAIL_SOFT_MIN_KB, AVAIL_SOFT_MAX_KB);
    }

    if (t->avail_soft_kb < t->avail_hard_kb) t->avail_soft_kb = t->avail_hard_kb;
}

double oom_update_baseline(double baseline, double sample, double alpha) {
    if (alpha <= 0) alpha = 0.01;
    if (alpha > 1)  alpha = 1;
    if (sample < 0) sample = 0;
    return baseline + alpha * (sample - baseline);
}

oom_verdict oom_decide_v2(const mem_state *m, const thresholds *t, double psi_baseline, int sustain_count) {
    oom_verdict v;
    v.action = ACT_NONE; v.reason = RS_NONE; v.psi_baseline = psi_baseline;
    v.avail_soft_kb = t->avail_soft_kb; v.avail_hard_kb = t->avail_hard_kb;

    int have_avail = (m->mem_avail_kb >= 0);

    /* 1. real starvation: almost no memory left; kill at once, no sustain, regardless of PSI */
    if (have_avail && m->mem_avail_kb <= t->avail_hard_kb) {
        v.action = ACT_HARD; v.reason = RS_AVAIL;
        return v;
    }

    /* under long load the PSI baseline is high by itself; the threshold rises with it */
    double psi_hard_eff = t->psi_hard;
    double from_baseline = psi_baseline * t->baseline_k;
    if (from_baseline > psi_hard_eff) psi_hard_eff = from_baseline;

    int scarce = have_avail && m->mem_avail_kb <= t->avail_soft_kb;

    /* 2. pressure with real scarcity: soft first, hard if it persists */
    if (scarce && m->psi_full_avg10 >= psi_hard_eff) {
        v.action = (sustain_count + 1 >= t->sustain_n) ? ACT_HARD : ACT_SOFT;
        v.reason = RS_PSI_SCARCE;
        return v;
    }
    if (scarce) {
        v.action = ACT_SOFT; v.reason = RS_AVAIL;
        return v;
    }

    /* 3. pressure without scarcity is swap/page-cache thrashing, not starvation: do not kill */
    if (m->psi_full_avg10 >= psi_hard_eff || m->psi_some_avg10 >= t->psi_soft) {
        v.action = ACT_WARN; v.reason = RS_THRASH;
        return v;
    }
    return v;
}

oom_action oom_decide(const mem_state *m, const thresholds *t) {
    return oom_decide_v2(m, t, 0.0, 0).action;
}

long oom_parse_meminfo_field(const char *buf, const char *key) {
    size_t kl = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0) {
            p += kl;
            while (*p == ' ' || *p == '\t') p++;
            long v = 0; int got = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; got = 1; }
            return got ? v : -1;
        }
        const char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : 0;
    }
    return -1;
}

long oom_parse_meminfo_avail(const char *buf) {
    return oom_parse_meminfo_field(buf, "MemAvailable:");   /* /proc/meminfo is already in kB */
}

int oom_parse_psi_line(const char *buf, const char *kind, double *avg10) {
    size_t kl = strlen(kind);
    const char *p = buf;
    while (p && *p) {
        if (strncmp(p, kind, kl) == 0 && p[kl] == ' ') {
            const char *a = strstr(p, "avg10=");
            if (a) { *avg10 = atof(a + 6); return 0; }
            return -1;
        }
        const char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : 0;
    }
    return -1;
}

/* find a key ONLY at the start of a line; return a pointer just past it, or NULL */
static const char *line_find(const char *buf, const char *key) {
    size_t kl = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0) return p + kl;
        const char *nl = strchr(p, '\n');
        p = nl ? nl + 1 : 0;
    }
    return 0;
}

static long status_field(const char *buf, const char *key) {
    const char *p = line_find(buf, key);
    if (!p) return 0;
    while (*p && (*p < '0' || *p > '9')) { if (*p == '\n') return 0; p++; }
    long v = 0; while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
    return v;
}

int oom_parse_status(const char *buf, proc_sample *p) {
    const char *n = line_find(buf, "Name:");
    p->comm[0] = 0;
    if (n) {
        while (*n == ' ' || *n == '\t') n++;
        int i = 0; while (*n && *n != '\n' && i < OOM_COMM_MAX - 1) p->comm[i++] = *n++;
        p->comm[i] = 0;
    }
    const char *s = line_find(buf, "State:");
    p->state = '?';
    if (s) { while (*s == ' ' || *s == '\t') s++; p->state = *s; }
    p->rss_kb  = status_field(buf, "VmRSS:");
    p->swap_kb = status_field(buf, "VmSwap:");
    p->ppid = (int)status_field(buf, "PPid:");
    return 0;
}

int oom_parse_zram_mmstat(const char *buf, long *orig_kb, long *compr_kb, long *total_kb) {
    long vals[3] = {0,0,0};
    const char *p = buf; int i = 0;
    while (*p && i < 3) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p < '0' || *p > '9') break;
        long v = 0; while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        vals[i++] = v;
    }
    if (i < 3) return -1;
    *orig_kb = vals[0] / 1024; *compr_kb = vals[1] / 1024; *total_kb = vals[2] / 1024;
    return 0;
}

/* comm in /proc/pid/stat is in parentheses and may contain spaces and ')': search for the LAST ')' */
int oom_parse_stat(const char *buf, int *tty_nr, unsigned long long *start_ticks) {
    const char *p = strrchr(buf, ')');
    if (!p) return -1;
    p++;
    /* after ')' comes field 3 (state); tty_nr = field 7, starttime = field 22 */
    int field = 2;
    *tty_nr = 0; *start_ticks = 0;
    int got_tty = 0, got_start = 0;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p || *p == '\n') break;
        const char *tok = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        field++;
        if (field == 7)  { *tty_nr = atoi(tok); got_tty = 1; }
        if (field == 22) { *start_ticks = strtoull(tok, 0, 10); got_start = 1; break; }
    }
    return (got_tty && got_start) ? 0 : -1;
}

unsigned oom_classify_cgroup(const char *buf, char *out, int outlen) {
    unsigned flags = 0;
    const char *path = strstr(buf, "0::");
    if (!path) path = strchr(buf, '/');
    else path += 3;
    if (!path) { if (out && outlen > 0) out[0] = 0; return 0; }

    int len = 0;
    while (path[len] && path[len] != '\n') len++;

    if (out && outlen > 0) {
        /* the tail of the path says more than the head: keep the end when truncating */
        int copy = len < outlen - 1 ? len : outlen - 1;
        const char *src = path + (len - copy);
        memcpy(out, src, (size_t)copy);
        out[copy] = 0;
        if (copy < len) flags |= PF_CG_TRUNC;   /* a truncated path does not address a cgroup */
    }
    if (strncmp(path, "/system.slice", 13) == 0) flags |= PF_SYSTEM_SVC;
    if (strncmp(path, "/aegis-freeze/", 14) == 0) flags |= PF_FROZEN;
    return flags;   /* PF_SESSION comes from an open GPU node, not from the cgroup */
}

/* The only GUI marker a child process does not inherit: an open /dev/dri
 * node. The terminal and the desktop shell hold one, a compiler does not.
 * WAYLAND_DISPLAY in the environment does not work: every child of a terminal inherits it. */
int oom_link_is_gui(const char *link) {
    return strncmp(link, "/dev/dri/", 9) == 0;
}

int oom_cgroup_killable(const char *cg) {
    if (!cg || !cg[0]) return 0;
    size_t n = strlen(cg);
    /* kill only a leaf: scope or service. A slice is a branch with unrelated processes */
    int is_scope   = (n > 6 && strcmp(cg + n - 6, ".scope") == 0);
    int is_service = (n > 8 && strcmp(cg + n - 8, ".service") == 0);
    if (!is_scope && !is_service) return 0;

    const char *leaf = strrchr(cg, '/');
    leaf = leaf ? leaf + 1 : cg;
    if (strncmp(leaf, "session-", 8) == 0) return 0;   /* the whole login session */
    if (strncmp(leaf, "user@", 5) == 0)    return 0;   /* the user manager */
    if (strcmp(leaf, "init.scope") == 0)   return 0;
    if (strncmp(leaf, "aegis", 5) == 0) return 0;   /* never ourselves or our siblings */
    return 1;
}
