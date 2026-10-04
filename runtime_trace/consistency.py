"""The checks themselves: pure comparison logic, no kernel access, no eBPF, no I/O.

Each check takes plain Python data (snapshots RuntimeTrace already collected) and returns Finding objects.
This is deliberate: it is the same shape as PhantomTrace's checks, and it means every check here can be
proven correct with a fake scenario in the test suite, with no root and no real kernel needed to run the tests.

A rootkit or hiding technique usually works by making one kernel-exposed view disagree with another, or by
making userland tools disagree with what the kernel actually did. Each check below is exactly one such
comparison. None of them require guessing at intent; they report a disagreement and explain what it usually means.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

SEVERITIES = ("high", "medium", "low")

WHY = {
    "hidden_process": (
        "A process that the kernel scheduler reported running does not appear when this computer's own process "
        "list is read. This is the classic effect of a loadable-kernel-module rootkit hooking the directory-read "
        "or process-list code path to hide one of its own processes. It can also happen, rarely, if a very "
        "short-lived process exited in the instant between the two reads; a repeat scan rules that out."
    ),
    "memfd_fileless_exec": (
        "A program was executed straight from anonymous memory (a memfd, or a file descriptor with no path on "
        "disk) rather than from a file. This is a well-known way to run code that never touches the disk, used "
        "by both fileless malware and some anti-forensic loaders, because there is no file for a disk-based scan "
        "or PhantomTrace-style check to ever find."
    ),
    "hidden_module_sysfs": (
        "A kernel module appears in one kernel-exposed listing but not the other (/proc/modules vs /sys/module). "
        "Simple LKM rootkits hide themselves by unlinking from the list /proc/modules walks, but forget that "
        "/sys/module is backed by a separate kobject tree. A module present in only one of the two is worth a "
        "second look; it is not always malicious (some modules do this deliberately for other reasons)."
    ),
    "ld_preload_global": (
        "/etc/ld.so.preload is the system-wide list of shared libraries the dynamic linker loads into every new "
        "process, before anything else. It is empty on almost every normal system. A populated file is a classic "
        "way to inject code into every process on the machine (a common userland rootkit technique) and is worth "
        "reading in full."
    ),
    "ld_preload_process": (
        "This process's environment sets LD_PRELOAD to a library outside the usual system locations. That "
        "library's code runs inside the process before its own code does. This is routine for some debugging and "
        "profiling tools, but it is also how userland code injection is done, so an unexpected one is worth checking."
    ),
    "deleted_exe_running": (
        "This process is running from a binary that no longer exists on disk (its /proc/<pid>/exe symlink is "
        "marked '(deleted)'). On almost every real system this is the ordinary, harmless result of a package "
        "upgrade replacing a binary or library that a long-running process (a desktop daemon is a common "
        "example) still has open; it will clear up next time that process restarts. The same symlink marking "
        "is also how a payload can be run, then deleted, leaving nothing on disk for an offline scan to find "
        "while it keeps running in memory, which is why it is still worth a glance rather than filtering out."
    ),
}

# Libraries that live alongside a confined (snap/flatpak) app's own bundle are not injected by an attacker,
# they are that app's own sandbox-compatibility shims, and a bare name with no path (resolved via the normal
# dynamic-linker search path) is not how a path-based LD_PRELOAD injection is done either.
STANDARD_LIB_DIRS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                     "/snap/", "/var/lib/snapd/", "/var/lib/flatpak/")


@dataclass
class Finding:
    check: str
    severity: str
    pid: int | None
    name: str
    message: str

    def as_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity, "pid": self.pid, "name": self.name, "message": self.message, "why": WHY[self.check]}


@dataclass
class ProcSnapshot:
    """Userland's own view of the system at one instant: exactly what `ps`, `lsmod` and friends would show."""
    pids: set[int] = field(default_factory=set)                       # every pid currently in /proc
    exe_targets: dict[int, str] = field(default_factory=dict)         # pid -> resolved target of /proc/<pid>/exe
    environ: dict[int, dict[str, str]] = field(default_factory=dict)  # pid -> parsed /proc/<pid>/environ (best effort)
    modules_proc: set[str] = field(default_factory=set)               # names from /proc/modules
    modules_sysfs: set[str] = field(default_factory=set)              # directory names from /sys/module
    ld_preload_file: str = ""                                         # contents of /etc/ld.so.preload, stripped


@dataclass
class KernelExec:
    """One process-execution event, as the kernel itself reported it (via eBPF). Ground truth: this really ran."""
    pid: int
    ppid: int
    comm: str
    filename: str
    ts: float = 0.0


def check_hidden_processes(execs: Iterable[KernelExec], proc: ProcSnapshot, still_running: set[int] | None = None) -> list[Finding]:
    """A pid the kernel told us about that is not in this process's own /proc listing."""
    out = []
    for e in execs:
        if still_running is not None and e.pid not in still_running:
            continue    # it already exited: not hidden, just gone, and that is not this check's business
        if e.pid not in proc.pids:
            out.append(Finding("hidden_process", "high", e.pid, e.comm or "?",
                                f"pid {e.pid} ({e.comm or '?'}) executed and has not exited, but is missing from this computer's own process list"))
    return out


def check_fileless_exec(execs: Iterable[KernelExec]) -> list[Finding]:
    out = []
    for e in execs:
        f = e.filename or ""
        if f.startswith("memfd:") or f.startswith("/memfd:") or re_fd_path(f):
            out.append(Finding("memfd_fileless_exec", "high", e.pid, e.comm or "?", f"pid {e.pid} ({e.comm or '?'}) was executed from '{f}', not from a file on disk"))
    return out


def re_fd_path(f: str) -> bool:
    import re
    return bool(re.match(r"^/proc/(self|\d+)/fd/\d+$", f))


def check_hidden_modules(proc: ProcSnapshot) -> list[Finding]:
    out = []
    for name in sorted(proc.modules_sysfs - proc.modules_proc):
        out.append(Finding("hidden_module_sysfs", "high", None, name, f"module '{name}' has a /sys/module entry but does not appear in /proc/modules"))
    for name in sorted(proc.modules_proc - proc.modules_sysfs):
        out.append(Finding("hidden_module_sysfs", "medium", None, name, f"module '{name}' appears in /proc/modules but has no /sys/module entry"))
    return out


def check_ld_preload(proc: ProcSnapshot, allow_dirs: tuple[str, ...] = STANDARD_LIB_DIRS) -> list[Finding]:
    out = []
    if proc.ld_preload_file.strip():
        first = proc.ld_preload_file.strip().splitlines()[0]
        out.append(Finding("ld_preload_global", "high", None, "/etc/ld.so.preload", f"/etc/ld.so.preload is not empty: {first!r}"))
    for pid, env in proc.environ.items():
        v = env.get("LD_PRELOAD", "").strip()
        if not v:
            continue
        paths = [p for p in v.split(":") if p]
        outside = [p for p in paths if "/" in p and not any(p.startswith(d) for d in allow_dirs)]
        if outside:
            out.append(Finding("ld_preload_process", "medium", pid, str(pid), f"pid {pid} has LD_PRELOAD={v!r}"))
    return out


def check_deleted_exe(proc: ProcSnapshot) -> list[Finding]:
    out = []
    for pid, target in proc.exe_targets.items():
        if target.endswith(" (deleted)"):
            out.append(Finding("deleted_exe_running", "low", pid, str(pid), f"pid {pid} is running from {target}"))
    return out


def run_all(execs: Iterable[KernelExec], proc: ProcSnapshot, still_running: set[int] | None = None) -> list[Finding]:
    execs = list(execs)
    findings: list[Finding] = []
    findings += check_hidden_processes(execs, proc, still_running)
    findings += check_fileless_exec(execs)
    findings += check_hidden_modules(proc)
    findings += check_ld_preload(proc)
    findings += check_deleted_exe(proc)
    return findings


def verdict(findings: list[Finding]) -> tuple[str, str]:
    n = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    if n["high"]:
        return "red", f"{n['high']} high-severity inconsistenc{'y' if n['high'] == 1 else 'ies'} found. Verify with a second tool before drawing conclusions."
    if n["medium"]:
        return "yellow", f"{n['medium']} medium-severity issue(s) found."
    if findings:
        return "cyan", "Only low-confidence notes."
    return "green", "No runtime inconsistencies found."
