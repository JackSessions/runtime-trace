"""The CLI's own behaviour: exit codes, --list-checks, --version, colour switching. Runs against this real
computer's /proc (read-only, no root), the same as test_procfs.py, so these are not mocked end-to-end tests."""
import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_trace import cli  # noqa: E402
from runtime_trace.term import Style  # noqa: E402


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:                        # --help / --version / --list-checks exit via argparse
            code = e.code if isinstance(e.code, int) else 0
    return code, out.getvalue(), err.getvalue()


class ExitCodeTests(unittest.TestCase):
    def test_a_real_run_with_only_low_findings_exits_clean(self):
        # On almost any real machine the instant (no --watch) mode finds at most low-severity notes
        # (a package-upgrade "(deleted)" binary); that must never fail a script's exit-code check.
        code, out, err = run(["-q"])
        self.assertEqual(code, 0)
        self.assertIn("confidence", out.lower() or "no runtime" in out.lower() or out)

    def test_json_is_valid_and_matches_the_quiet_verdict(self):
        code_q, out_q, _ = run(["-q"])
        code_j, out_j, _ = run(["--json"])
        self.assertEqual(code_q, code_j)
        d = json.loads(out_j)
        self.assertEqual(d["verdict"], out_q.strip())
        self.assertIn("meta", d)
        self.assertIn("findings", d)


class ListChecksTests(unittest.TestCase):
    def test_lists_every_check_and_flags_the_two_that_need_root(self):
        code, out, _ = run(["--list-checks"])
        self.assertEqual(code, 0)
        for name in ("hidden_process", "memfd_fileless_exec", "hidden_module_sysfs", "ld_preload_global", "ld_preload_process", "deleted_exe_running"):
            self.assertIn(name, out)
        self.assertIn("hidden_process (needs --watch, root)", out)
        self.assertNotIn("hidden_module_sysfs (needs --watch, root)", out)


class VersionAndHelpTests(unittest.TestCase):
    def test_version_prints_and_exits_zero(self):
        code, out, _ = run(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.0", out)

    def test_help_mentions_every_check_and_the_root_requirement(self):
        code, out, _ = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("hidden_process", out)
        self.assertIn("live checks need root", out.lower())


class StyleTests(unittest.TestCase):
    def test_colour_off_means_plain_text(self):
        st = Style(False)
        self.assertEqual(st("red", "x"), "x")
        self.assertEqual(st.google("a\nb"), "a\nb")

    def test_colour_on_wraps_in_ansi(self):
        st = Style(True)
        self.assertIn("\x1b[", st("red", "x"))

    def test_wordmark_colours_each_character_and_leaves_spaces_alone(self):
        from runtime_trace.term import BANNER
        st = Style(True)
        on, off = st.wordmark(BANNER), Style(False).wordmark(BANNER)
        self.assertEqual(off, BANNER)                     # colour off: byte-for-byte the plain ASCII art
        self.assertIn("\x1b[", on)
        self.assertEqual(on.count(" "), BANNER.count(" "))  # no colour codes glued onto blank space

    def test_the_wordmark_is_real_recognisable_ascii_art(self):
        from runtime_trace.term import BANNER, BANNER_PRETTY
        self.assertEqual(len(BANNER.split("\n")), 4)       # the figlet block is exactly 4 rows
        for banner in (BANNER, BANNER_PRETTY):
            self.assertIn("_", banner)
            self.assertIn("|", banner)


class ReportGroupingAndPrettyTests(unittest.TestCase):
    def test_a_repeated_check_is_grouped_with_a_count_not_one_line_each(self):
        from runtime_trace.consistency import Finding
        # the real-world case that motivated this: a dozen gvfs daemons all showing "(deleted)" after an
        # ordinary package upgrade must read as one group, not twelve near-identical lines.
        findings = [Finding("deleted_exe_running", "low", i, str(i), f"pid {i} is running from /x{i} (deleted)") for i in range(12)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_report(findings, {"watched_seconds": 0, "exec_events_seen": 0, "processes_now": 1, "modules_now": 1, "notes": []}, "cyan", "Only low-confidence notes.", Style(False))
        text = out.getvalue()
        self.assertIn("deleted_exe_running x12", text)
        self.assertEqual(text.count("pid "), cli.MAX_PER_GROUP)          # only the shown examples; the "N more" line names no pids
        self.assertIn("7 more not shown", text)

    def test_pretty_mode_shows_bars_and_the_boxed_banner(self):
        from runtime_trace.term import bar
        from runtime_trace.consistency import Finding
        findings = [Finding("ld_preload_global", "high", None, "x", "x")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_report(findings, {"watched_seconds": 0, "exec_events_seen": 0, "processes_now": 1, "modules_now": 1, "notes": []}, "red", "1 high-severity inconsistency found.", Style(False), pretty=True)
        text = out.getvalue()
        self.assertIn("┌", text)
        self.assertIn("high", text)
        self.assertEqual(bar(0), "░" * 20)                # zero findings: an empty (all-hollow) bar
        self.assertEqual(bar(3), "█" * 3 + "░" * 17)       # some findings: a partially-filled bar

    def test_every_real_verdict_colour_works_with_colour_on(self):
        # consistency.verdict() can return "red", "yellow", "cyan" or "green"; this crashed in the default
        # (coloured, not -q/--json) report path for "cyan" (the common "only low-confidence notes" case)
        # because term.py's palette only defined blue/red/yellow/green. Every one of these must now render,
        # and an unrecognised name must degrade to plain text rather than ever raising.
        st = Style(True)
        for name in ("red", "yellow", "cyan", "green"):
            self.assertIn("\x1b[", st(name, "Verdict"))
        self.assertEqual(st("not-a-real-colour", "x"), "x")

    def test_the_pretty_banner_is_always_aligned(self):
        from runtime_trace.term import BANNER_PRETTY
        lines = BANNER_PRETTY.split("\n")
        self.assertEqual(len({len(ln) for ln in lines}), 1, f"banner lines are not the same width: {lines}")

    def test_the_coloured_report_path_renders_for_every_verdict(self):
        from runtime_trace.consistency import Finding
        st = Style(True)
        scenarios = {
            "green": [],
            "cyan": [Finding("deleted_exe_running", "low", 1, "1", "x")],
            "yellow": [Finding("ld_preload_global", "medium", None, "x", "x")],
            "red": [Finding("hidden_process", "high", 2, "2", "x")],
        }
        for expected_color, findings in scenarios.items():
            from runtime_trace.consistency import verdict
            color, msg = verdict(findings)
            self.assertEqual(color, expected_color)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli._print_report(findings, {"watched_seconds": 0, "exec_events_seen": 0, "processes_now": 1, "modules_now": 1, "notes": []}, color, msg, st)
            self.assertIn(msg, out.getvalue())


if __name__ == "__main__":
    unittest.main()
