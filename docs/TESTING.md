# Testing RuntimeTrace

## 1. Automated tests, no root (a few seconds)

```bash
cd ~/Projects/runtime-trace
python3 -m unittest discover -s tests -v
```

Expect **34 tests, OK, 1 skipped** (`test_watching_sees_a_real_exec`, which needs root). This covers every check's logic against fake scenarios, a real read of your own `/proc` and `/sys`, and the CLI's exit codes, `--list-checks`, `--version` and `--help`.

## 2. Automated tests, with root (proves the live eBPF collector)

Needs a real Linux machine and sudo, so it's on you to run it. It needs the real eBPF toolkit first:

```bash
sudo apt install python3-bpfcc        # Debian/Ubuntu; see README for Fedora/Arch
cd ~/Projects/runtime-trace
sudo python3 -m unittest discover -s "$(pwd)/tests" -v -p test_collector.py
```

(The `-s "$(pwd)/tests"` form uses an absolute path on purpose: `sudo python3 -m unittest tests.test_collector`
only works if you happen to be in the repo root already, and silently fails with `ModuleNotFoundError: No module
named 'tests'` from anywhere else, including a subdirectory of this same repo.)

Expect `test_watching_sees_a_real_exec` to **run** (not skip) and pass: it attaches the real probe, runs `/bin/true`, and checks the kernel actually told RuntimeTrace about it. **Confirmed passing** on a real machine as of this version. If it fails on yours, paste the exact error — a real cross-kernel incompatibility was already found and fixed this way once (see the README's "How it is tested"), so a new one is entirely plausible and worth reporting.

## 3. A five-minute manual run-through

```bash
runtime-trace --help                   # banner, every check listed, examples
runtime-trace --list-checks            # each check's explanation, flagged if it needs --watch/root
runtime-trace                          # instant mode: coloured, grouped report, no root
runtime-trace --pretty                 # the boxed-banner, severity-bar version
runtime-trace --json | python3 -m json.tool | head -30
runtime-trace --html /tmp/rt.html -q && xdg-open /tmp/rt.html   # or just open it manually
sudo runtime-trace --watch 20          # watch the live "N exec events seen, Ns left" line tick down
```

| Step | Expected |
|---|---|
| `--help` | Coloured banner (or plain text if piped/`NO_COLOR`), every check described, exit codes explained |
| plain run | A coloured report; on an ordinary machine, 0 findings or a few `[LOW] deleted_exe_running` notes only |
| `--watch 20` as root | A live progress line on stderr, then the report including `hidden_process`/`memfd_fileless_exec` if anything triggered them |
| `--watch` as non-root | A clear one-line error telling you to use `sudo`, not a stack trace |
| `--json` | Valid JSON; `verdict` matches what `-q` printed |
| `--no-color` / `| cat` | No ANSI escape codes, no box-drawing artifacts |

## 4. Things that should fail politely

```bash
runtime-trace --watch 5               # (as your normal user, no sudo) -> clear error, exit 2, not a traceback
NO_COLOR=1 runtime-trace              # -> plain text, no escape codes
```

## 5. Report a bug or a false positive

False positives are the most useful kind of report (two were already found and fixed building this: module-hiding and browser sandbox `LD_PRELOAD`, see the README). Open an issue with `runtime-trace --json` output and `uname -r`.
