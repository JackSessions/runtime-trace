"""Pure logic, no root, no kernel, no eBPF: every check gets a fake scenario and must fire exactly on it,
and a clean scenario must stay quiet. This is the same testing philosophy as PhantomTrace: a check that
cannot be proven both ways with ordinary unit tests is not trustworthy enough to ship."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_trace.consistency import (  # noqa: E402
    KernelExec, ProcSnapshot, check_deleted_exe, check_fileless_exec, check_hidden_modules,
    check_hidden_processes, check_ld_preload, run_all, verdict,
)


def clean_proc(pids=(1, 2, 3)) -> ProcSnapshot:
    return ProcSnapshot(pids=set(pids), exe_targets={p: f"/usr/bin/proc{p}" for p in pids},
                         environ={p: {"PATH": "/usr/bin"} for p in pids},
                         modules_proc={"ext4", "nf_tables"}, modules_sysfs={"ext4", "nf_tables"}, ld_preload_file="")


class CleanTests(unittest.TestCase):
    def test_a_fully_consistent_system_has_no_findings(self):
        proc = clean_proc()
        execs = [KernelExec(pid=p, ppid=1, comm=f"proc{p}", filename=f"/usr/bin/proc{p}") for p in proc.pids]
        self.assertEqual(run_all(execs, proc, still_running=set(proc.pids)), [])
        self.assertEqual(verdict([]), ("green", "No runtime inconsistencies found."))

    def test_a_bare_library_name_and_a_sandboxed_app_are_not_flagged(self):
        proc = clean_proc()
        proc.environ[1]["LD_PRELOAD"] = "libmozsandbox.so :/snap/firefox/8863/gnome-platform/lib/bindtextdomain.so"
        self.assertEqual(check_ld_preload(proc), [])


class HiddenProcessTests(unittest.TestCase):
    def test_a_pid_the_kernel_ran_but_proc_does_not_list_is_hidden(self):
        proc = clean_proc(pids=(1, 2))                 # pid 1337 missing from /proc entirely
        execs = [KernelExec(pid=1337, ppid=1, comm="evil", filename="/tmp/evil")]
        out = check_hidden_processes(execs, proc, still_running={1337})
        self.assertEqual([(f.check, f.severity, f.pid) for f in out], [("hidden_process", "high", 1337)])

    def test_a_pid_that_already_exited_is_not_flagged(self):
        proc = clean_proc(pids=(1, 2))
        execs = [KernelExec(pid=1337, ppid=1, comm="shortlived", filename="/bin/true")]
        self.assertEqual(check_hidden_processes(execs, proc, still_running=set()), [])

    def test_without_a_live_watch_window_this_check_is_simply_not_run(self):
        # run_all with no exec events (the --watch-less mode) cannot see hidden processes at all,
        # and must not pretend to by flagging anything.
        self.assertEqual(check_hidden_processes([], clean_proc(), still_running=set()), [])


class FilelessExecTests(unittest.TestCase):
    def test_memfd_and_anonymous_fd_paths_are_flagged(self):
        execs = [KernelExec(pid=5, ppid=1, comm="x", filename="/memfd:payload (deleted)"),
                 KernelExec(pid=6, ppid=1, comm="y", filename="/proc/self/fd/7"),
                 KernelExec(pid=7, ppid=1, comm="z", filename="/usr/bin/ls")]
        out = check_fileless_exec(execs)
        self.assertEqual(sorted(f.pid for f in out), [5, 6])
        self.assertTrue(all(f.severity == "high" for f in out))


class HiddenModuleTests(unittest.TestCase):
    def test_a_module_in_only_one_view_is_flagged(self):
        proc = clean_proc()
        proc.modules_sysfs = proc.modules_sysfs | {"rootkit_mod"}       # self-hid from /proc/modules, not /sys/module
        out = check_hidden_modules(proc)
        self.assertEqual([(f.check, f.severity, f.name) for f in out], [("hidden_module_sysfs", "high", "rootkit_mod")])

    def test_built_in_modules_are_never_in_modules_sysfs_so_never_flagged(self):
        # procfs.py filters /sys/module down to entries with a 'coresize' file before this ever runs;
        # here we just confirm the comparison itself agrees when both sides already match.
        self.assertEqual(check_hidden_modules(clean_proc()), [])


class LdPreloadTests(unittest.TestCase):
    def test_global_preload_file_is_flagged(self):
        proc = clean_proc()
        proc.ld_preload_file = "/tmp/.hidden/evil.so\n"
        out = check_ld_preload(proc)
        self.assertEqual([(f.check, f.severity) for f in out], [("ld_preload_global", "high")])

    def test_a_process_level_preload_outside_system_dirs_is_flagged(self):
        proc = clean_proc()
        proc.environ[1]["LD_PRELOAD"] = "/tmp/.hidden/evil.so"
        out = check_ld_preload(proc)
        self.assertEqual([(f.check, f.severity, f.pid) for f in out], [("ld_preload_process", "medium", 1)])

    def test_a_preload_inside_standard_lib_dirs_is_not_flagged(self):
        proc = clean_proc()
        proc.environ[1]["LD_PRELOAD"] = "/usr/lib/x86_64-linux-gnu/libasan.so"
        self.assertEqual(check_ld_preload(proc), [])


class DeletedExeTests(unittest.TestCase):
    def test_a_deleted_running_binary_is_a_low_confidence_note(self):
        proc = clean_proc()
        proc.exe_targets[1] = "/usr/libexec/gvfsd (deleted)"
        out = check_deleted_exe(proc)
        self.assertEqual([(f.check, f.severity, f.pid) for f in out], [("deleted_exe_running", "low", 1)])


class VerdictTests(unittest.TestCase):
    def test_severity_ordering(self):
        proc = clean_proc()
        proc.ld_preload_file = "x"
        self.assertEqual(verdict(run_all([], proc, set()))[0], "red")


if __name__ == "__main__":
    unittest.main()
