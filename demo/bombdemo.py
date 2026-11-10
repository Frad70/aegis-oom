#!/usr/bin/env python3
"""aegis-oom demo: a cgroup with a RAM limit and a memory bomb, killed by the real daemon.

The daemon watches the pressure of this test cgroup only (AEG_OOM_PSI_PATH points at its
memory.pressure) and picks victims only inside it (--scope). If the daemon misses the bomb,
the kernel cgroup OOM fires at the hard limit; the host is not affected.

Usage:   sudo python3 demo/bombdemo.py [--mem-max 4G] [--mem-high 3G]
                                       [--psi-soft 10] [--psi-hard 25] [--seconds 25]
"""
import argparse, os, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN  = os.path.join(REPO, "aegis-oom")
CG   = "/sys/fs/cgroup/oom-bomb"
ST   = "/tmp/oom-bomb.state"
LOG  = "/tmp/oom-bomb.daemon.log"

BOMB = (
    "import signal,time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"   # ignore SIGTERM so the escalation to SIGKILL is visible
    "chunks=[]\n"
    "while True:\n"
    "    b=bytearray(50*1024*1024)\n"
    "    for i in range(0,len(b),4096): b[i]=1\n"
    "    chunks.append(b)\n"
    "    time.sleep(0.03)\n"                              # ~1.6 GB/s
)


def w(p, v):
    open(p, "w").write(v)


def rd(p, d=""):
    try:
        return open(p).read().strip()
    except Exception:
        return d


def psi(field):
    for ln in rd(CG + "/memory.pressure").splitlines():
        if ln.startswith(field):
            for tok in ln.split():
                if tok.startswith("avg10="):
                    return tok.split("=")[1]
    return "?"


def events(key):
    for ln in rd(CG + "/memory.events").splitlines():
        if ln.startswith(key + " "):
            return ln.split()[1]
    return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mem-max", default="4G")
    ap.add_argument("--mem-high", default="3G")
    ap.add_argument("--psi-soft", default="10")
    ap.add_argument("--psi-hard", default="25")
    ap.add_argument("--seconds", type=float, default=25.0)
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Root is required: sudo python3 demo/bombdemo.py")
    if not os.path.exists(BIN):
        sys.exit("binary %s not found; build it: make -C %s aegis-oom" % (BIN, REPO))

    daemon = bomb = None
    try:
        subprocess.run(["rmdir", CG], stderr=subprocess.DEVNULL)
        os.makedirs(CG, exist_ok=True)
        w(CG + "/memory.max", a.mem_max)
        for path, val in ((CG + "/memory.high", a.mem_high), (CG + "/memory.swap.max", "0")):
            try: w(path, val)
            except Exception: pass

        env = {**os.environ,
               "AEG_OOM_PSI_SOFT": a.psi_soft, "AEG_OOM_PSI_HARD": a.psi_hard,
               "AEG_OOM_RATE_MS": "400", "AEG_OOM_REFRESH_MS": "500",
               "AEG_OOM_PSI_PATH": CG + "/memory.pressure"}
        dlog = open(LOG, "w")
        daemon = subprocess.Popen(
            [BIN, "--live", "--no-arm", "--no-conf", "--no-learn",
             "--scope", CG, "--protect", "__none__", "--state", ST],
            stdout=dlog, stderr=dlog, env=env)
        time.sleep(0.7)

        bomb = subprocess.Popen([sys.executable, "-c", BOMB])
        w(CG + "/cgroup.procs", str(bomb.pid))
        print("daemon pid=%d  bomb pid=%d  cgroup=%s (max=%s high=%s swap=0)\n"
              % (daemon.pid, bomb.pid, CG, a.mem_max, a.mem_high), flush=True)

        t0 = time.time(); died = None
        while time.time() - t0 < a.seconds:
            used = int(rd(CG + "/memory.current", "0") or 0) // (1024 * 1024)
            alive = bomb.poll() is None
            print("t=%4.1fs  used=%5dMB  PSI some=%-6s full=%-6s  bomb=%s"
                  % (time.time() - t0, used, psi("some"), psi("full"),
                     "alive" if alive else "DEAD"), flush=True)
            if not alive and died is None:
                died = time.time()
            if died and time.time() - died > 1.5:
                break
            time.sleep(0.5)

        print("\n=== what the daemon logged ===", flush=True)
        for ln in rd(LOG).splitlines():
            if any(k in ln for k in ("KILL", "armed", "DRYRUN")):
                print("   " + ln, flush=True)
        print("\n=== who killed it: memory.events ===", flush=True)
        print("   oom_kill (kernel cgroup OOM)=%s   limit hits (max)=%s"
              % (events("oom_kill"), events("max")), flush=True)
        print("   oom_kill=0 means the daemon killed it before the kernel reached the hard limit\n",
              flush=True)
    finally:
        for p in (bomb, daemon):
            if p:
                try: p.kill()
                except Exception: pass
        subprocess.run(["rmdir", CG], stderr=subprocess.DEVNULL)
        for f in (ST, LOG):
            try: os.remove(f)
            except Exception: pass


if __name__ == "__main__":
    main()
