from __future__ import annotations

import argparse
import json as json_mod
import os
import sys
import time

from . import __author__, __url__, __version__
from . import procfs
from . import term
from .collector import Collector, CollectorError
from .consistency import WHY, Finding, KernelExec, run_all, verdict
from .report import html_report
from .term import SEV_COLOR, Style


class _Help(argparse.Action):
    """-h / --help: shows the banner first when talking to a terminal."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if sys.stdout.isatty():
            term.enable_windows_ansi()
            st = Style("NO_COLOR" not in os.environ)
            print(st.wordmark(term.BANNER.strip("\n")) + "\n" + st("dim", f"  v{__version__}  |  {term.SUBTITLE}") + "\n")
        parser.print_help()
        parser.exit()


def _run(duration: float, st: Style) -> tuple[list[Finding], dict]:
    """Takes a procfs snapshot now; if duration > 0, also watches live execs for that long first (needs root)."""
    execs: list[KernelExec] = []
    still_running: set[int] | None = None
    notes: list[str] = []
    if duration > 0:
        c = Collector()
        try:
            c.attach()
        except CollectorError as e:
            if os.geteuid() != 0:
                raise CollectorError(f"{e}\n\nLive monitoring needs root: try `sudo runtime-trace --watch {duration:g}`.") from e
            raise
        tty = sys.stderr.isatty()

        def progress(n: int) -> None:
            if tty:
                remaining = max(0, int(end - time.time()))
                sys.stderr.write(f"\r  {st('blue', 'watching')}  {n} exec event(s) seen, {remaining}s left  ")
                sys.stderr.flush()
        end = time.time() + duration
        c.run_for(duration, progress=progress)
        if tty:
            sys.stderr.write("\r" + " " * 50 + "\r")
            sys.stderr.flush()
        execs, still_running = c.execs, set(c.still_running)
        c.close()
    else:
        notes.append("No --watch duration given: only the checks that read /proc and /sys ran. "
                      "Hidden-process and fileless-execution detection need a live watch window and root.")
    proc = procfs.snapshot()
    findings = run_all(execs, proc, still_running)
    meta = {"watched_seconds": duration, "exec_events_seen": len(execs), "processes_now": len(proc.pids),
            "modules_now": len(proc.modules_proc), "notes": notes, "version": __version__}
    return findings, meta


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="runtime-trace", add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "RuntimeTrace: a runtime cross-layer consistency checker for Linux, powered by eBPF.\n\n"
            "A healthy system's kernel-level truth (what actually ran) agrees with what userland tools like\n"
            "`ps` and `lsmod` report. Process-hiding rootkits and some anti-forensic tricks make those\n"
            "disagree. RuntimeTrace checks:\n\n"
            "  hidden_process        a pid the kernel scheduler ran, missing from /proc (needs --watch, root)\n"
            "  memfd_fileless_exec   a program executed from memory, never from a file on disk (needs --watch, root)\n"
            "  hidden_module_sysfs   /proc/modules and /sys/module disagree about what is loaded\n"
            "  ld_preload_global     /etc/ld.so.preload (loaded into every new process) is not empty\n"
            "  ld_preload_process    a process has LD_PRELOAD set to something outside the system library paths\n"
            "  deleted_exe_running   a running process's binary no longer exists on disk"),
        epilog=(
            "examples:\n"
            "  runtime-trace                       instant check: /proc and /sys only, no root needed\n"
            "  sudo runtime-trace --watch 30        also watch live process execution for 30 seconds\n"
            "  runtime-trace --json                 machine-readable output, for scripts\n"
            "  runtime-trace --html report.html     a shareable report\n"
            "  runtime-trace --list-checks          every check, its severity and what it means\n"
            "  runtime-trace --pretty                an extra-visual report: a boxed banner and severity bars\n\n"
            "exit codes:  0 clean   1 high/medium findings   2 error\n\n"
            "notes:\n"
            "  * Read-only: never kills, hides or modifies anything; only observes and reports.\n"
            "  * Findings are leads, not proof. Confirm anything serious with a second tool.\n"
            "  * The live checks need root (a kernel rule, not a choice this tool makes).\n\n"
            f"Created by {__author__} | MIT licence | {__url__}"))
    ap.add_argument("-h", "--help", action=_Help, help="show this help message and exit")
    g = ap.add_argument_group("what to watch")
    g.add_argument("--watch", type=float, default=0, metavar="SECONDS", help="also watch live process execution for this long (needs root)")
    g = ap.add_argument_group("output")
    g.add_argument("--json", action="store_true", help="print machine-readable JSON instead of the report")
    g.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    g.add_argument("-q", "--quiet", action="store_true", help="print only the verdict")
    g.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is also honoured)")
    g.add_argument("--pretty", action="store_true", help="an extra-visual report: a boxed banner and severity bars")
    g = ap.add_argument_group("information")
    g.add_argument("--list-checks", action="store_true", help="list every check with its severity and meaning, then exit")
    g.add_argument("--version", action="version", version=f"runtime-trace {__version__}")
    term.enable_windows_ansi()
    a = ap.parse_args(argv)

    if a.list_checks:
        needs_root = {"hidden_process", "memfd_fileless_exec"}
        for name, why in WHY.items():
            tag = " (needs --watch, root)" if name in needs_root else ""
            print(f"{name}{tag}\n  {why}\n")
        return 0

    st = Style(term.color_ok(a.no_color))
    try:
        findings, meta = _run(a.watch, st)
    except CollectorError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"Permission denied: {e}. Some checks need root to read other users' processes.", file=sys.stderr)
        return 2

    color, msg = verdict(findings)
    if a.json:
        print(json_mod.dumps({"version": __version__, "verdict": msg, "meta": meta, "findings": [f.as_dict() for f in findings]}, indent=2))
    elif a.quiet:
        print(msg)
    else:
        _print_report(findings, meta, color, msg, st, pretty=a.pretty)
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(html_report(findings, meta))
        if not a.quiet and not a.json:
            print(f"\nWrote {a.html}")
    return 0 if not any(f.severity in ("high", "medium") for f in findings) else 1


MAX_PER_GROUP = 5


def _print_report(findings: list[Finding], meta: dict, color: str, msg: str, st: Style, pretty: bool = False) -> None:
    if pretty:
        print(st.google(term.BANNER_PRETTY))
    else:
        print(st.wordmark(term.BANNER.rstrip("\n")))
    print(st("dim", f"  v{__version__}  |  {term.SUBTITLE}"))
    print()
    print(f"  {st('bold', 'Watched')} {meta['watched_seconds']:g}s, {meta['exec_events_seen']} exec event(s) · "
          f"{meta['processes_now']} process(es) now · {meta['modules_now']} module(s) now")
    print()
    for n in meta["notes"]:
        print(f"  {st('dim', 'note:')} {n}\n")

    # Grouped by check (in WHY's declared order), not one line per finding: a check that fires a dozen times
    # on an ordinary machine (gvfs daemons after a package upgrade is the common real example) should read as
    # one group with a count, not a wall of near-identical lines.
    shown = 0
    for check in WHY:
        group = [f for f in findings if f.check == check]
        if not group:
            continue
        sev = group[0].severity
        print(f"  {st(SEV_COLOR[sev], f'[{sev.upper()}]')} {st('bold', check)} {st('dim', f'x{len(group)}')}")
        for f in group[:MAX_PER_GROUP]:
            shown += 1
            print(f"      {st('dim', chr(0x2022))} {f.message}")
        if len(group) > MAX_PER_GROUP:
            print(f"      {st('dim', f'... {len(group) - MAX_PER_GROUP} more not shown (use --json for all)')}")
        print()

    counts = {s: sum(x.severity == s for x in findings) for s in ("high", "medium", "low")}
    if pretty:
        for s in ("high", "medium", "low"):
            print(f"  {st(SEV_COLOR[s], f'{s:7}')} {st(SEV_COLOR[s], term.bar(counts[s]))}  {counts[s]}")
        print()
    else:
        print(f"  {st('bold', 'Summary')}  " + "  ".join(st(SEV_COLOR[s], f"{s} {n}") for s, n in counts.items()))
    print(f"  {st(color, 'Verdict')}  {msg}")


if __name__ == "__main__":
    raise SystemExit(main())
