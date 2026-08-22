#!/usr/bin/env python3

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


EVAL_ROOT = Path(__file__).resolve().parents[1]
SOURCE = EVAL_ROOT / "workload" / "gap_probe.c"
APP_LOG = Path("/tmp/startup-gap-app.log")


class GapProbeLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("cc is required for gap probe tests")
        cls.temporary_directory = tempfile.TemporaryDirectory(
            prefix="gap-probe-test-"
        )
        cls.binary = Path(cls.temporary_directory.name) / "gap-launch"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-o",
                str(cls.binary),
                str(SOURCE),
            ],
            check=True,
            text=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def run_probe(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        completed = subprocess.run(
            [str(self.binary), *arguments],
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
        )
        records = [json.loads(line) for line in completed.stdout.splitlines()]
        return completed, records

    def test_synthetic_mode_preserves_original_event_contract(self) -> None:
        completed, records = self.run_probe(
            "--interval-us",
            "5000",
            "--duration-ms",
            "20",
            "--evidence-hold-ms",
            "1",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(records[0]["event"], "probe_start")
        self.assertEqual(records[-1]["event"], "probe_summary")
        self.assertNotIn("application", records[0])
        self.assertNotIn("application", records[-1])
        self.assertTrue(
            all(record["event"] in {"probe_start", "attempt", "probe_summary"}
                for record in records)
        )

    def test_application_is_alive_at_summary_and_cleaned_up(self) -> None:
        completed, records = self.run_probe(
            "--interval-us",
            "5000",
            "--duration-ms",
            "20",
            "--evidence-hold-ms",
            "1",
            "--application",
            "sleeper",
            "--",
            "/bin/sleep",
            "10",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        start = next(record for record in records if record["event"] == "probe_start")
        spawn = next(record for record in records if record["event"] == "app_spawn")
        summary = next(
            record for record in records if record["event"] == "probe_summary"
        )
        app_exit = next(record for record in records if record["event"] == "app_exit")
        self.assertEqual(start["application"], "sleeper")
        self.assertLess(records.index(spawn), records.index(summary))
        self.assertTrue(summary["app_alive_at_summary"])
        self.assertEqual(app_exit["phase"], "cleanup")
        self.assertEqual(app_exit["term_signal"], 15)

    def test_early_application_exit_is_nonzero(self) -> None:
        completed, records = self.run_probe(
            "--interval-us",
            "5000",
            "--duration-ms",
            "100",
            "--evidence-hold-ms",
            "1",
            "--application",
            "exits",
            "--",
            "/bin/true",
        )

        self.assertNotEqual(completed.returncode, 0)
        summary = next(
            record for record in records if record["event"] == "probe_summary"
        )
        app_exit = next(record for record in records if record["event"] == "app_exit")
        self.assertFalse(summary["app_alive_at_summary"])
        self.assertEqual(app_exit["phase"], "measurement")
        self.assertEqual(app_exit["exit_code"], 0)

    def test_application_stdout_and_stderr_are_redirected(self) -> None:
        command = (
            "printf 'app-stdout\\n'; printf 'app-stderr\\n' >&2; "
            "exec /bin/sleep 10"
        )
        completed, records = self.run_probe(
            "--interval-us",
            "5000",
            "--duration-ms",
            "20",
            "--evidence-hold-ms",
            "1",
            "--application",
            "logging",
            "--",
            "/bin/sh",
            "-c",
            command,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("app-stdout", completed.stdout)
        self.assertNotIn("app-stderr", completed.stdout)
        self.assertEqual(
            next(record for record in records if record["event"] == "app_spawn")[
                "log_path"
            ],
            str(APP_LOG),
        )
        log_text = APP_LOG.read_text(encoding="utf-8")
        self.assertIn("app-stdout", log_text)
        self.assertIn("app-stderr", log_text)


if __name__ == "__main__":
    unittest.main()
