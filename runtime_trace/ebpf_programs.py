"""The eBPF program itself: a small, read-only probe compiled and loaded by BCC at runtime.

It does exactly two things: whenever any process on this computer executes a program, and whenever any process
exits, it tells userspace. That is the kernel's own ground truth about what ran, straight from the scheduler,
before any userland tool (and anything that may have hooked one) gets a chance to filter it.

Deliberately NOT read here: the executed filename. `sched_process_exec`'s tracepoint format carries it as a
`__data_loc` string, and the exact struct field BCC generates for that turned out to differ across real
kernels in testing (it compiled fine on one machine and failed with "no member named 'filename'" on another,
same BCC version). Rather than add fragile, kernel-version-specific C to chase that, the filename is resolved
in plain Python instead, straight after this event arrives: see Collector._on_exec in collector.py. `pid` and
`comm` below are the two fields this needed to prove stable across kernels; keep any new field just as small.

It never writes to kernel memory, never modifies behaviour, and never affects the processes it watches. It only
reads data the kernel was already producing and copies it out through a perf ring buffer, which is the standard,
supported way eBPF tracing tools (bpftrace, Falco, Tetragon and others) are built.
"""
from __future__ import annotations

# TASK_COMM_LEN is 16 on every Linux kernel RuntimeTrace targets.
PROGRAM = r"""
#include <linux/sched.h>

#define TASK_COMM_LEN 16

struct exec_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct exit_event_t {
    u32 pid;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(exit_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t data = {};
    data.pid = args->pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct exit_event_t data = {};
    data.pid = args->pid;
    exit_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""
