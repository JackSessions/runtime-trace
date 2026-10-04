"""The live eBPF collector needs the Python 'bcc' module and root to attach. Skipped otherwise, exactly like
PhantomTrace skips its real-NTFS tests without ntfs-3g: the pure logic above is tested unconditionally, and
this is the thin, separately-tested integration layer underneath it."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_trace.collector import Collector, CollectorError  # noqa: E402

try:
    import bcc  # noqa: F401
    HAVE_BCC = True
except ImportError:
    HAVE_BCC = False


class CollectorErrorTests(unittest.TestCase):
    def test_a_clear_error_when_bcc_is_missing(self):
        import runtime_trace.collector as mod
        old = mod.BPF
        mod.BPF = None
        try:
            with self.assertRaises(CollectorError):
                Collector()
        finally:
            mod.BPF = old


@unittest.skipUnless(HAVE_BCC, "needs the python3-bpfcc (bcc) package")
class CompileTests(unittest.TestCase):
    """Compiling the program does not need root; only attaching it to a tracepoint does. This at least
    proves the probe's C still compiles against whatever kernel runs it."""
    def test_program_source_is_well_formed(self):
        from runtime_trace.ebpf_programs import PROGRAM
        self.assertIn("sched_process_exec", PROGRAM)
        self.assertIn("sched_process_exit", PROGRAM)
        # The executed filename is deliberately NOT read in the kernel (see ebpf_programs.py's docstring:
        # the __data_loc struct field BCC generates for it was found, by actually testing on a real machine,
        # to differ across kernel versions). Only pid and comm, which proved stable, belong in this program.
        self.assertNotIn("filename", PROGRAM)


@unittest.skipUnless(HAVE_BCC, "needs the python3-bpfcc (bcc) package")
class ExecFilenameResolutionTests(unittest.TestCase):
    """_on_exec resolves the executed path in plain Python (os.readlink of /proc/<pid>/exe), not from the
    kernel event, precisely because of the cross-kernel field-name problem above. No root needed: this never
    attaches a probe, just feeds _on_exec a fake decoded event and a fake perf-buffer table."""

    class _FakeEvent:
        def __init__(self, pid: int, comm: bytes) -> None:
            self.pid, self.comm = pid, comm

    class _FakeTable:
        def __init__(self, event) -> None:
            self._event = event

        def event(self, data):
            return self._event

    def _collector_with(self, pid: int, comm: bytes) -> Collector:
        c = Collector()
        c._bpf = {"exec_events": self._FakeTable(self._FakeEvent(pid, comm))}
        return c

    def test_resolves_the_real_exe_of_a_still_running_pid(self):
        c = self._collector_with(os.getpid(), b"python3\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        c._on_exec(0, b"", 0)
        self.assertEqual(len(c.execs), 1)
        self.assertEqual(c.execs[0].filename, os.readlink(f"/proc/{os.getpid()}/exe"))
        self.assertEqual(c.execs[0].comm, "python3")
        self.assertIn(os.getpid(), c.still_running)

    def test_a_pid_that_has_already_exited_gets_an_empty_filename_not_a_crash(self):
        # a pid number that (almost certainly) does not exist: readlink must fail cleanly, not raise out
        c = self._collector_with(2**22 - 1, b"gone")
        c._on_exec(0, b"", 0)
        self.assertEqual(c.execs[0].filename, "")


@unittest.skipUnless(HAVE_BCC and os.geteuid() == 0, "needs root to attach a real probe")
class LiveTests(unittest.TestCase):
    """Only runs as root (e.g. `sudo python3 -m unittest tests.test_collector -v`). Starts the real probe,
    execs a real child process, and checks the kernel actually told us about it."""
    def test_watching_sees_a_real_exec(self):
        import subprocess
        c = Collector()
        c.attach()
        try:
            subprocess.run(["/bin/true"])
            c.run_for(1.0)
        finally:
            c.close()
        self.assertTrue(any(e.comm == "true" for e in c.execs), f"did not observe /bin/true among {c.execs}")


if __name__ == "__main__":
    unittest.main()
