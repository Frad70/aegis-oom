#ifndef OOM_POLICY_H
#define OOM_POLICY_H

#define OOM_COMM_MAX      32
#define OOM_CGROUP_MAX    128
#define OOM_MAX_PROTECT   32
#define OOM_MAX_PROCS     8192
#define OOM_ADJ_IMMUNE    (-1000)
/* oom_score_adj acts as a multiplier (1 + adj/1000): a kernel hint must not
 * lift small processes above the real hogs (adj=+300 on browser helpers). */
#define OOM_ADJ_SCALE     1000.0

/* process traits for protection scoring (filled in during enrichment) */
#define PF_ENRICHED   0x01   /* stat/cgroup/fd read, the flags below are reliable */
#define PF_SESSION    0x02   /* holds a GPU node open => a GUI app */
#define PF_TTY        0x04   /* has a controlling terminal */
#define PF_SYSTEM_SVC 0x08   /* system.slice: a systemd service */
#define PF_SELF       0x10   /* the daemon itself, its parent or its session leader */
#define PF_CG_TRUNC   0x20   /* cgroup path did not fit the buffer: never kill by it */
#define PF_FROZEN     0x40   /* in a frozen cgroup under /oom-freezer/ */
#define PF_PROTECTED_TREE 0x80 /* descendant of a protected application */

typedef struct {
    int  pid;
    int  ppid;
    long rss_kb;
    long swap_kb;
    int  oom_score_adj;
    char state;                       /* R,S,D,Z,T,I,... */
    char comm[OOM_COMM_MAX];
    /* enrichment, 0 until PF_ENRICHED is set */
    unsigned flags;
    long age_s;                       /* process age in seconds */
    long growth_kb;                   /* rss+swap growth since the last sample, kB */
    unsigned long long start_ticks;   /* start time: tells the process apart from a namesake with the same pid */
    char cgroup[OOM_CGROUP_MAX];      /* tail of the cgroup v2 path */
} proc_sample;

typedef struct {
    char names[OOM_MAX_PROTECT][OOM_COMM_MAX];
    int  count;
} protect_list;

typedef enum { ACT_NONE = 0, ACT_WARN = 1, ACT_SOFT = 2, ACT_HARD = 3 } oom_action;

typedef enum { RS_NONE = 0, RS_AVAIL = 1, RS_PSI_SCARCE = 2, RS_THRASH = 3,
               RS_FORCED = 4 /* --force: thresholds play no part */ } oom_reason;

typedef struct {
    double psi_some_avg10;
    double psi_full_avg10;
    long   mem_avail_kb;              /* -1 if unknown */
    long   mem_total_kb;              /* 0 if unknown */
    long   swap_free_kb;              /* -1 if unknown */
    long   swap_total_kb;             /* 0 if there is no swap */
    long   zswap_kb;                  /* compressed pool actually occupying RAM */
    long   cached_kb;
    long   sreclaimable_kb;
} mem_state;

typedef struct {
    double psi_soft;
    double psi_hard;
    long   avail_soft_kb;
    long   avail_hard_kb;
    double avail_soft_pct;            /* 0 = do not use percentages */
    double avail_hard_pct;
    double baseline_k;                /* how many times above the baseline counts as a spike */
    int    sustain_n;                 /* consecutive samples a level must hold before a kill */
    int    protect_smart;             /* 1 = take process traits into account */
} thresholds;

/* the decision uses memory state + PSI baseline; the verdict carries the reason */
typedef struct {
    oom_action action;
    oom_reason reason;
    double     psi_baseline;          /* smoothed psi_full baseline at decision time */
    long       avail_soft_kb;         /* thresholds actually applied (after percentages) */
    long       avail_hard_kb;
} oom_verdict;

int        oom_parse_protect(const char *csv, protect_list *pl);
int        oom_is_protected(const char *comm, const protect_list *pl);
int        oom_ancestry_boundary(const char *comm);
long       oom_victim_score(const proc_sample *p, const protect_list *pl, const thresholds *t);
int        oom_pick_victim(const proc_sample *procs, int n, const protect_list *pl, const thresholds *t);

/* thresholds in kB from percentages of MemTotal (when set), clamped to sane bounds */
void       oom_resolve_thresholds(const mem_state *m, thresholds *t);
/* PSI baseline: exponential smoothing, alpha as a fraction (0..1) */
double     oom_update_baseline(double baseline, double sample, double alpha);
/* pure decision: sustain_count = consecutive samples the level has already held >= SOFT */
oom_verdict oom_decide_v2(const mem_state *m, const thresholds *t, double psi_baseline, int sustain_count);
/* wrapper over v2 without baseline or accumulation */
oom_action oom_decide(const mem_state *m, const thresholds *t);

long oom_parse_meminfo_avail(const char *buf);
long oom_parse_meminfo_field(const char *buf, const char *key);
int  oom_parse_psi_line(const char *buf, const char *kind, double *avg10);
int  oom_parse_status(const char *buf, proc_sample *p);
int  oom_parse_zram_mmstat(const char *buf, long *orig_kb, long *compr_kb, long *total_kb);
/* /proc/pid/stat: tty_nr (field 7) and starttime (field 22), both after comm in parentheses */
int  oom_parse_stat(const char *buf, int *tty_nr, unsigned long long *start_ticks);
/* /proc/pid/cgroup -> path tail + PF_SYSTEM_SVC flag */
unsigned oom_classify_cgroup(const char *buf, char *out, int outlen);
/* readlink target of /proc/pid/fd/N: a GPU node = the process draws, so it is a GUI */
int  oom_link_is_gui(const char *link);
/* whether a whole cgroup may be killed: only a leaf scope/service, never a session or slice */
int  oom_cgroup_killable(const char *cg);

#endif
