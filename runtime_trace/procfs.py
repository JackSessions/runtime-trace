"""Reads this computer's own /proc and /sys, the userland view that `ps`, `lsmod` and friends also use.

Read-only. Every permission error on another user's process is swallowed and simply means that process is
skipped (not flagged): RuntimeTrace only reports a disagreement it was actually able to observe, never a
guess about something it could not read.
"""
from __future__ import annotations

import os

from .consistency import ProcSnapshot


def snapshot() -> ProcSnapshot:
    s = ProcSnapshot()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        s.pids.add(pid)
        try:
            s.exe_targets[pid] = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass                                       # kernel threads, and processes that just exited
        env = _read_environ(pid)
        if env:
            s.environ[pid] = env
    s.modules_proc = _modules_from_proc()
    s.modules_sysfs = _modules_from_sysfs()
    s.ld_preload_file = _read_text("/etc/ld.so.preload")
    return s


def _read_environ(pid: int) -> dict[str, str]:
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
    except OSError:
        return {}                                       # needs root for other users' processes; that is fine
    out = {}
    for part in raw.split(b"\0"):
        if b"=" in part:
            k, _, v = part.partition(b"=")
            try:
                out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
            except Exception:
                continue
    return out


def _modules_from_proc() -> set[str]:
    try:
        with open("/proc/modules", "r", encoding="utf-8", errors="replace") as f:
            return {ln.split()[0] for ln in f if ln.strip()}
    except OSError:
        return set()


def _modules_from_sysfs() -> set[str]:
    """Only dynamically *loaded* modules, like /proc/modules: /sys/module also lists every module built
    into the kernel (never loaded, nothing to hide), which only exposes a 'parameters' directory and no
    'coresize' file. A loaded module always has 'coresize' (its size in memory), built-in modules never do."""
    try:
        return {d for d in os.listdir("/sys/module") if os.path.isfile(f"/sys/module/{d}/coresize")}
    except OSError:
        return set()


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""
