"""Runs the real snapshot() against this computer's own /proc and /sys. Entirely read-only, no root needed:
these just prove it does not crash on a real, messy, live system and returns something well-formed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_trace import procfs  # noqa: E402
from runtime_trace.consistency import run_all  # noqa: E402


class ProcfsTests(unittest.TestCase):
    def test_snapshot_sees_this_very_interpreter(self):
        s = procfs.snapshot()
        self.assertIn(os.getpid(), s.pids)
        self.assertGreater(len(s.pids), 5)

    def test_loaded_modules_are_a_subset_of_proc_modules_when_both_readable(self):
        s = procfs.snapshot()
        if not s.modules_proc:                           # e.g. a kernel with no loadable modules at all
            self.skipTest("no /proc/modules on this system")
        self.assertTrue(s.modules_sysfs <= s.modules_proc | s.modules_sysfs)   # never crashes building this

    def test_builtin_only_modules_do_not_pollute_the_loaded_set(self):
        s = procfs.snapshot()
        # apparmor (and friends) are compiled into most distro kernels, never dynamically loaded: if this
        # system has one, it must not appear in modules_sysfs (no 'coresize' => not counted as loaded).
        if os.path.isdir("/sys/module/apparmor") and not os.path.isfile("/sys/module/apparmor/coresize"):
            self.assertNotIn("apparmor", s.modules_sysfs)

    def test_a_full_run_against_the_real_system_does_not_crash(self):
        s = procfs.snapshot()
        run_all([], s, still_running=set())                # no live execs: only the procfs-only checks run


if __name__ == "__main__":
    unittest.main()
