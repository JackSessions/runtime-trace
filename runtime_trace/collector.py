"""Loads the eBPF program and turns its perf-buffer output into KernelExec / pid-exit events.

Needs root (or CAP_BPF + CAP_PERFMON on a kernel that supports splitting them out) to attach: reading and
compiling the program does not need special privilege, but loading it into the kernel and attaching it to a
tracepoint does. That is a kernel-enforced rule, not a choice RuntimeTrace makes.
"""
from __future__ import annotations

import os
import time

from .consistency import KernelExec

try:
    from bcc import BPF
except ImportError:                                   # bcc (python3-bpfcc) is a real dependency, not optional
    BPF = None

from .ebpf_programs import PROGRAM


class CollectorError(Exception):
    pass


def _compile_quietly() -> "BPF":
    """BCC's underlying clang writes compiler diagnostics straight to the real stderr file descriptor, which a
    Python try/except cannot catch or inspect. On success this just means the terminal stays clean. On failure
    that is a real problem: silence would hide the one piece of information needed to fix it, so the real
    output is captured to a temp file instead of /dev/null, and its tail is folded into the exception that
    CollectorError.attach() raises, so the actual compiler error is still visible, just through Python."""
    import tempfile
    fd, path = tempfile.mkstemp(prefix="runtime-trace-compile-")
    saved = os.dup(2)
    try:
        os.dup2(fd, 2)
        return BPF(text=PROGRAM.encode())                # bytes, not str: avoids a harmless but noisy BCC DeprecationWarning
    except Exception as e:
        os.dup2(saved, 2)                               # restore stderr before printing/reading
        with open(path, "r", errors="replace") as f:
            captured = f.read().strip()
        tail = "\n".join(captured.splitlines()[-12:]) if captured else ""
        raise RuntimeError(f"{e}" + (f"\n\ncompiler said:\n{tail}" if tail else "")) from e
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass


class Collector:
    """Attaches the probe, then `run_for(seconds)` yields events while they happen.

    `still_running` is kept up to date as events arrive, so a caller doing a hidden-process check partway
    through a run always has an accurate "has this pid exited yet?" set to compare against.
    """

    def __init__(self) -> None:
        if BPF is None:
            raise CollectorError("The 'bcc' Python module is not installed (Debian/Ubuntu: `sudo apt install python3-bpfcc`).")
        self.execs: list[KernelExec] = []
        self.still_running: set[int] = set()
        self._bpf: "BPF | None" = None

    def attach(self) -> None:
        try:
            self._bpf = _compile_quietly()
        except Exception as e:                         # BCC raises plain Exception on compile/load failure
            raise CollectorError(f"Could not load the eBPF program: {e}") from e
        self._bpf["exec_events"].open_perf_buffer(self._on_exec)
        self._bpf["exit_events"].open_perf_buffer(self._on_exit)

    def _on_exec(self, cpu, data, size) -> None:
        e = self._bpf["exec_events"].event(data)
        comm = e.comm.decode("utf-8", "replace").rstrip("\x00")
        pid = int(e.pid)
        self.still_running.add(pid)
        # The executed path is not read in the kernel (see ebpf_programs.py for why): resolved here instead,
        # the same way procfs.py reads any other process's /proc/<pid>/exe. This can race a process that exits
        # between the kernel telling us about the exec and this read; filename is "" when that happens, which
        # the fileless-exec check simply does not match, so a miss here is silent, never a crash.
        try:
            filename = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            filename = ""
        self.execs.append(KernelExec(pid=pid, ppid=0, comm=comm, filename=filename, ts=time.time()))

    def _on_exit(self, cpu, data, size) -> None:
        e = self._bpf["exit_events"].event(data)
        self.still_running.discard(int(e.pid))

    def run_for(self, seconds: float, progress=None) -> None:
        """Poll the perf buffers for `seconds`. Call repeatedly (or with a long duration) for live monitoring."""
        assert self._bpf is not None, "call attach() first"
        end = time.time() + seconds
        while time.time() < end:
            self._bpf.perf_buffer_poll(timeout=200)
            if progress:
                progress(len(self.execs))

    def close(self) -> None:
        self._bpf = None
