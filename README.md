# aegis-oom

Two small Linux daemons that keep a desktop or server responsive when memory
or process count runs out:

- `aegis-oom`, a userspace OOM killer driven by memory pressure (PSI) and
  available memory. It picks the process whose death frees the most memory
  with the least damage, and signals it before the kernel OOM killer would act
  or the machine starts thrashing.
- `aegis-reaper`, a fork bomb killer. When the task count of a watched cgroup
  passes a threshold, it kills the leaf cgroup with the most tasks through
  `cgroup.kill`.

Both run pre-armed: locked in RAM (`mlockall`), with `oom_score_adj=-1000` and
`SCHED_FIFO` priority, so they still get memory and CPU time when the rest of
the system does not. Neither forks or allocates on the hot path.

## Why

The kernel OOM killer acts late, after the machine has spent minutes in swap
or page cache thrashing, and it often kills a large long-running process that
was not the cause. Tools like earlyoom act earlier but rank by the kernel's
`oom_score`.
aegis-oom waits for real scarcity, weighs what a process is (GUI app, system
service, fresh and growing job), and prefers the process that is growing now.

A fork bomb leaves no room to fork a shell or a recovery tool. Only a process
that is already running can stop it.

## Build

Requirements: a C11 compiler, make, Linux headers. No other dependencies.

```sh
make            # builds aegis-oom and aegis-reaper
make test       # offline unit tests
```

## Install

```sh
sudo make install                    # PREFIX=/usr/local by default
sudo make install PREFIX=/opt/aegis-oom
```

`install.sh` builds both binaries (the reaper statically when a static libc is
available), installs them to `$PREFIX/bin`, the README to
`$PREFIX/share/doc/aegis-oom`, the config to `/etc/aegis/aegis-oom.conf` (an
existing config is kept and the new default goes next to it as
`aegis-oom.conf.default`), and the units `aegis-oom.service` and
`aegis-reaper.service` with `@PREFIX@` replaced. It then enables and restarts
both services.

The OOM killer starts in dry run: it logs what it would kill and writes its
state file, but kills nothing. Watch it for a while, then set
`AEG_OOM_DRYRUN=0` and run `systemctl reload aegis-oom`.

```sh
journalctl -u aegis-oom -u aegis-reaper -f
cat /run/aegis/oom.state
sudo make uninstall                  # or ./uninstall.sh --purge to drop the config
```

The reaper unit watches `/sys/fs/cgroup/user.slice` with a threshold of 8000
tasks and never kills a leaf with fewer than 300 tasks. Change the `ExecStart`
arguments with `systemctl edit aegis-reaper` if your normal load is higher.
A `TasksMax` limit on user slices complements the reaper; it is not installed.

## How aegis-oom decides

Every cycle reads `/proc/meminfo` and the root cgroup `memory.pressure`.
A PSI trigger wakes the loop at once when stalls appear; otherwise it polls,
every 1.5 s when close to a threshold and every 6 s when far from one. The
`/proc` scan for candidates runs only when it can matter.

The verdict, in order:

1. `MemAvailable` at or below the hard threshold: HARD, act at once.
2. `MemAvailable` at or below the soft threshold and PSI `full avg10` at or
   above the hard PSI level: SOFT, becoming HARD after `AEG_OOM_SUSTAIN_N`
   consecutive samples.
3. Soft scarcity alone: SOFT.
4. High PSI without scarcity: WARN only. Pressure with free memory is swap or
   page cache thrashing; killing would not help.

The hard PSI level is not fixed: it is the larger of `AEG_OOM_PSI_HARD` and
`AEG_OOM_BASELINE_K` times a smoothed PSI baseline. A machine that always runs
under some pressure needs a bigger spike before anything is killed. The
baseline is learned continuously and saved to `/var/lib/aegis/learned` every
five minutes and on exit, so a reboot does not reset it.

SOFT sends SIGTERM. If the same process is still alive after
`AEG_OOM_TERM_GRACE_MS`, it gets SIGKILL. HARD sends SIGKILL. At most one kill
happens per `AEG_OOM_RATE_MS`, and a new victim is not picked while the
previous one is still exiting within the grace period.

### The victim score

The score starts from resident memory plus a quarter of swapped memory (swap
is capped at the resident size, so a mostly swapped idle app is not the
scapegoat), plus twice the growth since the last sample. With
`AEG_OOM_PROTECT_SMART=1` it is then discounted:

| Trait | Factor |
|---|---|
| holds a `/dev/dri` node open (a GUI app of the live session) | 0.15 |
| runs in `system.slice` | 0.60 |
| older than a day / an hour | 0.35 / 0.60 |
| younger than a minute | 1.25 |

The kernel hint `oom_score_adj` multiplies the score by `1 + adj/1000`, so a
small helper with a positive adjustment does not outrank a process ten times
its size. Traits are read for the 32 largest candidates and for any candidate
that becomes the winner, so the decision never rests on unread traits.

### What is protected

Never a victim, whatever the config says:

- PID 1, the daemon itself, its parent and its session leader;
- processes with `oom_score_adj=-1000`;
- kernel threads and zombies (no resident memory);
- processes in a frozen cgroup under `/sys/fs/cgroup/oom-freezer/`;
- names in `AEG_OOM_PROTECT`, and their descendants. Inheritance stops at
  shells, terminals, compositors, `systemd` and `sshd`, so protecting one app
  started from a terminal does not protect everything else started there.

Right before the signal, the victim is pinned with `pidfd_open`, its start time
and its protection are checked again, and the signal goes through the pidfd.
A reused PID can never become a victim by accident.

With `AEG_OOM_CGROUP_KILL=1`, a SIGKILL may take the victim's whole leaf
cgroup (a `.scope` or `.service`) through `cgroup.kill`, so a build dies as a
unit. Login sessions, `user@` managers, `init.scope`, slices, cgroups with
children and cgroups with a protected member always get a single signal.

### State file

`/run/aegis/oom.state` is rewritten every cycle (only after a complete write).
It holds the verdict, PSI values, the baseline, memory figures, the ranked
candidate list and the last kill. A monitor that shows the file can touch
`/run/aegis/watch`; while its mtime is less than three seconds old, every
cycle refreshes the candidate list.

## The reaper

Every 250 ms the reaper reads `pids.current` of the watched cgroup. Above the
threshold it walks the subtree, finds the leaf cgroup with the most tasks, and
writes `1` to its `cgroup.kill`, polling every 50 ms until the count drains.
A leaf smaller than the minimum, a leaf with children, a login session scope,
a slice, the daemons' own units and any leaf with a protected member are never
killed. Its built-in protect list covers `systemd`, `sshd`, D-Bus, PipeWire,
Xorg and common compositors; a non-empty `AEG_OOM_PROTECT` replaces it.

A cgroup path written to `/run/aegis/reaper_target` is killed under the same
checks on the next poll, then the file is removed. This lets another root
tool hand a confirmed bomb to the reaper.

## Configuration

`/etc/aegis/aegis-oom.conf` is plain `KEY=value`, never executed as shell.
Values from the environment go through the same parser and range checks.
Precedence: built-in default, environment, config file, command line.
`systemctl reload` rereads the file in both daemons.

| Key | Default | Range | Meaning |
|---|---|---|---|
| `AEG_OOM_DRYRUN` | 1 | 0..1 | log and write state only |
| `AEG_OOM_PSI_SOFT` | 20 | 0.1..100 | PSI `some avg10` for WARN; half of it selects the fast cycle |
| `AEG_OOM_PSI_HARD` | 40 | 0.1..100 | PSI `full avg10` that escalates under scarcity |
| `AEG_OOM_AVAIL_SOFT_PCT` | 4 | 0..90 | soft threshold, percent of MemTotal, clamped to 384 MiB..3 GiB |
| `AEG_OOM_AVAIL_HARD_PCT` | 1.5 | 0..90 | hard threshold, percent of MemTotal, clamped to 128 MiB..1 GiB |
| `AEG_OOM_AVAIL_SOFT_MB` | unset | 1..1048576 | explicit soft threshold, replaces the percentage |
| `AEG_OOM_AVAIL_HARD_MB` | unset | 1..1048576 | explicit hard threshold, replaces the percentage |
| `AEG_OOM_SUSTAIN_N` | 3 | 1..120 | samples before SOFT becomes HARD |
| `AEG_OOM_BASELINE_K` | 2 | 1..100 | spike factor over the PSI baseline |
| `AEG_OOM_BASELINE_ALPHA` | 0.02 | 0.0001..1 | baseline smoothing per 1.5 s cycle |
| `AEG_OOM_PROTECT_SMART` | 1 | 0..1 | apply the trait discounts |
| `AEG_OOM_CGROUP_KILL` | 0 | 0..1 | SIGKILL the whole leaf cgroup |
| `AEG_OOM_RATE_MS` | 2000 | 100..60000 | minimum time between kills |
| `AEG_OOM_TERM_GRACE_MS` | 8000 | 1000..60000 | SIGTERM grace before SIGKILL |
| `AEG_OOM_REFRESH_MS` | 1500 | 100..60000 | fast cycle |
| `AEG_OOM_IDLE_MS` | 6000 | 100..60000 | idle cycle, at least the fast cycle |
| `AEG_OOM_IDLE_SCAN_S` | 60 | 1..3600 | candidate refresh while idle |
| `AEG_OOM_PSI_STALL_US` | 150000 | 1..10000000 | PSI trigger stall, below the window |
| `AEG_OOM_PSI_WINDOW_US` | 1000000 | 500000..10000000 | PSI trigger window |
| `AEG_OOM_STATE` | `/run/aegis/oom.state` | absolute path | state file |
| `AEG_OOM_PROTECT` | empty | comm names | protected names, comma separated |
| `AEG_REAPER_DRYRUN` | 0 | 0..1 | reaper logs instead of killing; an invalid value means 1 |

Environment only: `AEG_OOM_CONF` (config path), `AEG_OOM_PSI_PATH` (pressure
file), `AEG_OOM_WATCH` (watch file), `AEG_CONF` and `AEG_REAPER_PROTECT` for
the reaper.

A `#` outside quotes starts a comment, also after a value. systemd
`EnvironmentFile` passes such comments on in the environment, and the daemons
strip them with the same parser.

Command line of `aegis-oom`: `--dry-run`, `--live`, `--protect LIST`,
`--state PATH`, `--conf PATH`, `--no-conf`, `--no-learn`, `--no-arm`,
`--scope CGROUP_DIR` (pick victims only from that cgroup), `--once` (one
decision, print the victim, exit) and `--force soft|hard` (with `--once` and
`--scope` only). Command line of `aegis-reaper`:
`aegis-reaper [THRESHOLD [WATCHED_CGROUP [LEAF_MIN]]]`.

## Tests

`make test` builds both daemons and runs the offline suites: the policy
library (`test_oom_policy.c`, the main regression suite), the daemon's config,
signal choice, guards and kill path (`test_oom_runtime.c`), the cgroup guard
on a fixture directory (`test_cgroup_guard.c`) and the reaper config
(`test_reaper.c`). They need no privileges, write only to `/tmp`, and never
touch real cgroups. Signals go only to children the tests fork themselves.

The root integration tests run real workloads in dedicated cgroups under
`/sys/fs/cgroup/aegis-*-<run id>` with `memory.max` and `pids.max` limits and
a watchdog, against a separate reaper instance, never the system one:

```sh
sudo tests/run.sh --list
sudo tests/run.sh --tier fast        # three smoke cases
sudo tests/run.sh --tier full        # fork bomb shapes, victim choice, cgroup.kill
```

Without root, passwordless sudo or cgroup v2 they print `SKIP` and exit 0.
`demo/bombdemo.py` (root) shows the daemon stopping a memory bomb inside a
limited cgroup.

## Limits

- Linux only. `aegis-oom` needs `pidfd_open` (Linux 5.3) and refuses to start
  without it. PSI (Linux 4.20, `CONFIG_PSI`) is optional: without a pressure
  file or trigger support it logs the fact and decides on `MemAvailable` alone,
  polling. On cgroup v1 victim choice still works, but cgroup traits and
  `AEG_OOM_CGROUP_KILL` do not, and `AEG_OOM_PSI_PATH=/proc/pressure/memory`
  is needed for PSI.
- `aegis-reaper` needs cgroup v2 with the pids controller and refuses to start
  without it. Killing needs `cgroup.kill` (Linux 5.14). If the watched cgroup
  does not exist yet, it waits for it.
- In a container without write access to `/sys/fs/cgroup`, `cgroup.kill` fails
  and aegis-oom falls back to a single signal; the reaper cannot kill at all.
- Both daemons are meant to run as root. Hardening failures (`mlockall`,
  `SCHED_FIFO`, `oom_score_adj`) are logged, not fatal.
- Protection matches `comm`, which is at most 15 characters and can be set by
  any process. It is a policy aid, not a security boundary.
- Scarcity is judged system wide. A memory limit on one cgroup is the
  kernel's job; `--scope` only limits where victims are picked.

## License

MIT, see LICENSE.
