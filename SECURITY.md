# Security

RuntimeTrace is a **read-only** monitoring tool. It never kills, modifies, hides or otherwise acts on a process; it only observes and reports.

## Design choices you can rely on

- It never writes to kernel memory. The eBPF program only reads data the kernel already produces (exec and exit events) and copies it out through a standard perf ring buffer, the same mechanism bpftrace, Falco and Tetragon are built on.
- It has no network access and makes no outbound connections.
- It never conceals its own presence, and it is not designed to evade any other monitoring tool. (If you are looking for anti-forensic or evasion tooling, this project, and I, are not the place: it exists to detect that kind of hiding, not to do it.)
- Loading and attaching the eBPF program needs root or `CAP_BPF`/`CAP_PERFMON`, a kernel-enforced requirement RuntimeTrace cannot and does not try to work around.

## Reporting a problem

Please open a private security advisory on GitHub (Security tab, "Report a vulnerability"), or an issue for anything that is not sensitive. Include the output of `runtime-trace --version`, your distribution and kernel version (`uname -r`), and steps to reproduce.

## Using findings responsibly

RuntimeTrace reports *inconsistencies*, not proof of compromise. Several checks have ordinary, innocent causes (a package upgrade, a sandboxed application's own compatibility shims); the README explains each one. Treat every finding as a lead to verify with a second tool before taking action on a production system.
