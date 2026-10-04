"""RuntimeTrace: a runtime cross-layer consistency checker for Linux.

Same idea as PhantomTrace, one layer up: a healthy system's kernel-level ground truth (every process that
actually executed, every module that actually loaded) agrees with what userland tools like `ps` and `lsmod`
report. Rootkits, process-hiding malware and some anti-forensic tricks work by making those layers disagree.
RuntimeTrace watches the kernel directly with eBPF and reports where they don't.

Read-only. Never kills a process, never hides anything, never modifies the kernel. Findings are leads to
verify, not proof: confirm anything serious with a second tool.
"""
from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Jack Sessions"
__url__ = "https://github.com/JackSessions/runtime-trace"
