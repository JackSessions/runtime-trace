# RuntimeTrace

![tests](https://github.com/JackSessions/runtime-trace/actions/workflows/test.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![licence](https://img.shields.io/badge/licence-MIT-blue)

A runtime cross-layer consistency checker for Linux, powered by eBPF.

[PhantomTrace](https://github.com/JackSessions/PhantomTrace) asks whether an offline NTFS disk agrees with itself. RuntimeTrace asks the same question one layer up, on a live Linux system: does the kernel's own ground truth about what is running agree with what `ps`, `lsmod` and friends report? Process-hiding rootkits and some anti-forensic techniques work by making exactly one of those views lie. RuntimeTrace watches the kernel directly with eBPF and reports where the views disagree.

```bash
sudo apt install python3-bpfcc          # the real eBPF toolkit (see "Install" before anything else)
runtime-trace                           # instant: checks that need no root, no watch window
sudo runtime-trace --watch 30           # also watches live process execution for 30 seconds
```

## Why would anyone use this?

Most host-based detection reads logs, or asks the OS questions through the normal APIs, the exact APIs a kernel-level rootkit can quietly lie to. RuntimeTrace instead asks the kernel's scheduler directly, through eBPF, which a rootkit would have to compromise the kernel itself to fool.

- Incident responders and blue teams get a fast, read-only second opinion on a live, possibly-compromised Linux host: hidden processes, fileless execution straight from memory, hidden kernel modules, and classic LD_PRELOAD / `ld.so.preload` injection.
- People learning rootkit detection get a small, readable reference implementation, built the same way as PhantomTrace: every check is a plain comparison between two data sources, and every check has a test that proves it fires on a fake "tampered" scenario and stays quiet on a clean one.
- Anyone hardening a Linux box can run the no-root checks any time, for free, with no watch window needed.

What it is not: an EDR, a replacement for `auditd`/Falco/Tetragon in production, or proof of compromise. It reports *inconsistencies*. A finding is a lead to verify with a second tool, not a verdict. See [Known limitations](#known-limitations).

## What it checks

| Check | Compares | Needs root + `--watch`? |
|---|---|---|
| `hidden_process` | A pid the kernel scheduler ran vs this computer's own `/proc` listing | Yes |
| `memfd_fileless_exec` | A program executed from a memfd or an anonymous file descriptor, never from a file on disk | Yes |
| `hidden_module_sysfs` | `/proc/modules` vs `/sys/module` (two different kernel-exposed views of loaded modules) | No |
| `ld_preload_global` | Whether `/etc/ld.so.preload` (loaded into every new process) is non-empty | No |
| `ld_preload_process` | A process's own `LD_PRELOAD` against the standard system library paths | No |
| `deleted_exe_running` | A running process's `/proc/<pid>/exe` against whether that file still exists | No |

The first two need a live watch window with root, because they depend on the kernel telling RuntimeTrace about an exec as it happens; the rest read `/proc` and `/sys` once and need no special privilege at all.

## Install

1. The real eBPF toolkit first. This is the one dependency that matters, and it is a system package, not something pip can install: the `bcc` name on PyPI is an unrelated math library, so RuntimeTrace deliberately does not list it as a dependency.

```bash
sudo apt install python3-bpfcc      # Debian / Ubuntu
sudo dnf install python3-bcc        # Fedora
sudo pacman -S bcc-python           # Arch
```

2. Then RuntimeTrace. Because BCC is a *system* package, a normal isolated pipx/venv install cannot see it, so pass `--system-site-packages` so it can:

```bash
pipx install --system-site-packages runtime-trace
# or, without pipx: python3 -m pip install --user runtime-trace
```

If you skip step 1, every command still runs: the checks that need no root work with no eBPF at all, and `--watch` fails with a clear message telling you which package to install.

## Use

```
runtime-trace                       instant: /proc and /sys checks only, no root needed
sudo runtime-trace --watch 30       also watch live process execution for 30 seconds
runtime-trace --json                machine-readable output
runtime-trace --html report.html    a shareable report
runtime-trace --list-checks         every check, its severity and what it means
runtime-trace --pretty              an extra-visual report: a boxed banner and severity bars
runtime-trace -q                    just the verdict (good for scripts)
```

Coloured in a terminal (Google-colour severities), plain text otherwise: disabled automatically for pipes, `NO_COLOR`, or `--no-color`. During `--watch`, a live line on stderr shows exec events seen and time left, so it never looks frozen. Findings are grouped by check, not one line each, so a check that fires a dozen times (a run of `gvfs` daemons after a package upgrade is the common real example) reads as one group with a count. Exit codes: `0` clean (or low-confidence notes only), `1` a high or medium finding, `2` error.

## What it looks like

A real run, on an ordinary, untampered development machine (`runtime-trace`, no `--watch`):

```
   ___          _   _          _____                
  | _ \_  _ _ _| |_(_)_ __  __|_   _| _ __ _ __ ___ 
  |   / || | ' \  _| | '  \/ -_)| || '_/ _` / _/ -_)
  |_|_\\_,_|_||_\__|_|_|_|_\___||_||_| \__,_\__\___|
  v0.1.0  |  runtime cross-layer consistency checker, via eBPF

  Watched 0s, 0 exec event(s) · 398 process(es) now · 238 module(s) now

  note: No --watch duration given: only the checks that read /proc and /sys ran. ...

  [LOW] deleted_exe_running x12
      • pid 7855 is running from /usr/libexec/gvfsd (deleted)
      • pid 7868 is running from /usr/libexec/gvfsd-fuse (deleted)
      • pid 8397 is running from /usr/libexec/gvfs-udisks2-volume-monitor (deleted)
      • pid 8419 is running from /usr/libexec/gvfs-gphoto2-volume-monitor (deleted)
      • pid 8424 is running from /usr/libexec/gvfs-goa-volume-monitor (deleted)
      ... 7 more not shown (use --json for all)

  Summary  high 0  medium 0  low 12
  Verdict  Only low-confidence notes.
```

A real figlet wordmark (font "small", the same family PhantomTrace's own banner uses), in colour a diagonal four-colour cycle through the Google palette across every character, the same spirit as PhantomTrace's rainbow banner, in this author's newer, calmer four-colour identity rather than a full hue spectrum.

The same run with `--pretty`, a boxed banner and a severity bar in place of the one-line summary:

```
  ┌────────────────────────────────────────────────────┐
  │  ___          _   _          _____                 │
  │ | _ \_  _ _ _| |_(_)_ __  __|_   _| _ __ _ __ ___  │
  │ |   / || | ' \  _| | '  \/ -_)| || '_/ _` / _/ -_) │
  │ |_|_\\_,_|_||_\__|_|_|_|_\___||_||_| \__,_\__\___| │
  │                                                    │
  │ runtime cross-layer consistency checker, via eBPF  │
  └────────────────────────────────────────────────────┘
  v0.1.0  |  runtime cross-layer consistency checker, via eBPF
  ...
  high    ░░░░░░░░░░░░░░░░░░░░  0
  medium  ░░░░░░░░░░░░░░░░░░░░  0
  low     ████████████░░░░░░░░  12

  Verdict  Only low-confidence notes.
```

The same wordmark, framed in a box that is sized to fit it exactly (built from the longest line, so it can never go out of alignment). In colour, each row of the box gets the next Google colour in turn; the plain version above cycles per character instead, for extra flair. Everything switches off automatically outside a real terminal, for `NO_COLOR`, or for `--no-color`.

## How it is tested

Every check is pure comparison logic over plain Python data, with no kernel access, exactly like PhantomTrace's NTFS checks: each one gets a fake "tampered" scenario it must fire on, and a fake clean scenario it must stay quiet on. That part of the test suite needs no root and no real kernel, and runs in CI on every commit.

The live eBPF collector is tested separately and only runs its real-attach test as root (`sudo python3 -m unittest tests.test_collector -v`); everywhere else it is skipped with a clear reason, the same pattern PhantomTrace uses for tests that need `ntfs-3g`. That root-only test has now actually been run, on a real machine, and passed: it attached the real probe, ran `/bin/true`, and confirmed the kernel told RuntimeTrace about it. A step-by-step checklist, including the root-only run, is in [docs/TESTING.md](docs/TESTING.md).

Two lessons from building this, left in on purpose:

- The first version of `hidden_module_sysfs` compared `/proc/modules` against every directory in `/sys/module`, and immediately flagged well over a hundred "hidden modules" on an ordinary, untampered development machine. The cause: `/sys/module` also lists every module *compiled into* the kernel, which is never loaded and has nothing to hide; `/proc/modules` correctly only lists dynamically loaded ones. The fix was to only count a `/sys/module` entry as "loaded" when it has a `coresize` file, which built-in modules never have. The same pass also found that Firefox's and Discord's own snap sandboxing routinely sets `LD_PRELOAD`, and that desktop `gvfs` daemons showing "(deleted)" after an ordinary package upgrade is completely normal; both are now handled so a clean, ordinarily-patched desktop reports nothing. A tool that cries wolf on a clean system gets ignored, so this got fixed before it ever shipped.
- The executed filename was originally read from the `sched_process_exec` tracepoint's kernel-generated struct. Testing on a second real machine found that struct's exact field layout is not stable across kernels: it compiled cleanly on one machine and failed with "no member named 'filename'" on another, same BCC version. Rather than chase kernel-specific C, the filename is now resolved in plain Python (`os.readlink` on `/proc/<pid>/exe`) the instant the event arrives, using only `pid` and `comm` from the kernel, which proved stable on both. This can race a very short-lived process that exits in that instant (the filename then reads as empty, silently, never a crash), an honest trade for working across more kernels without fragile, version-specific code.

## Known limitations

- Linux only.
- The live checks need root. That is a kernel-enforced rule (loading and attaching an eBPF program needs `CAP_BPF`/`CAP_PERFMON`, or root), not a choice this tool makes.
- The executed filename can race a very short-lived process. It is resolved from `/proc/<pid>/exe` right after the kernel reports an exec, not from the kernel event itself (see "How it is tested" for why); a process that exits in that instant leaves `filename` empty for that event rather than wrong.
- `ppid` is not yet populated on live exec events (reading the parent pid from kernel memory needs either kernel headers or a CO-RE/BTF build that this version does not yet do); it is always `0` for now.
- Process-exec and module checks only. Network-connection monitoring, container/namespace awareness, and syscall-level privilege-escalation detection are not implemented yet.
- Tested so far on two real Ubuntu-family machines with BTF enabled. If a check behaves differently on your distro or kernel, especially a false positive, please open an issue: those reports are the most valuable kind, and found two real bugs (see "How it is tested") before this ever reached a wider audience.
- A rootkit sophisticated enough to patch the kernel's own tracepoint infrastructure (not just hook userland-facing code paths) could in principle also fool the live checks. No runtime tool can be above the kernel it watches.
- The eBPF program is compiled on every run (BCC's model), not built once. This is what caused the cross-kernel bug above; a future version may move to a pre-built libbpf/CO-RE object for better portability and faster startup. Tracked as a real roadmap item, not promised.

## Credit and licence

Created and maintained by Jack Sessions. Parts of the code were written with AI assistance; every check is covered by the tests described above, and findings are leads to verify, not proof.

MIT licence (see [LICENSE](LICENSE)). RuntimeTrace is built on [BCC](https://github.com/iovisor/bcc) (Apache-2.0), which is not bundled and must be installed as a system package (see Install). If you use RuntimeTrace in a report, talk, course or another tool, please credit Jack Sessions and link https://github.com/JackSessions/runtime-trace ([CITATION.cff](CITATION.cff) has the details).
