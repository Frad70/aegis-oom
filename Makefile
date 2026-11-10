CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

.PHONY: all test install uninstall clean
all: aegis-oom aegis-reaper

aegis-oom: oom.c oom_policy.c oom_policy.h config_value.h cgroup_guard.h
	$(CC) $(CFLAGS) -o aegis-oom oom.c oom_policy.c

aegis-reaper: reaper.c oom_policy.c oom_policy.h config_value.h cgroup_guard.h
	$(CC) $(CFLAGS) -o aegis-reaper reaper.c oom_policy.c

test-oom-runtime: test_oom_runtime.c oom.c oom_policy.c oom_policy.h config_value.h cgroup_guard.h
	$(CC) $(CFLAGS) -o test-oom-runtime test_oom_runtime.c oom_policy.c

test-cgroup-guard: test_cgroup_guard.c oom_policy.c oom_policy.h cgroup_guard.h
	$(CC) $(CFLAGS) -o test-cgroup-guard test_cgroup_guard.c oom_policy.c

test-oom-policy: test_oom_policy.c oom_policy.c oom_policy.h
	$(CC) $(CFLAGS) -o test-oom-policy test_oom_policy.c oom_policy.c

test: all test-oom-policy test-oom-runtime test-cgroup-guard
	./test-oom-policy
	./test-oom-runtime
	./test-cgroup-guard

install:
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -f aegis-oom aegis-reaper test-oom-policy test-oom-runtime test-cgroup-guard
