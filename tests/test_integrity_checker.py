import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class IntegrityCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, XDG_STATE_HOME=str(self.root / "state"))
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.first = self.logs / "syslog"
        self.first.write_text("original\n")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "integrity-check"), *map(str, args)],
            capture_output=True, text=True, env=self.env, cwd=self.root,
        )

    def test_single_file_workflow(self):
        self.assertEqual(self.run_cli("init", self.first).stdout.strip(), "Hashes stored successfully.")
        self.assertEqual(self.run_cli("check", self.first).stdout.strip(), "Status: Unmodified")
        self.first.write_text("changed\n")
        changed = self.run_cli("check", self.first)
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("Status: Modified (Hash mismatch)", changed.stdout)
        self.assertEqual(self.run_cli("update", self.first).stdout.strip(), "Hash updated successfully.")
        self.assertEqual(self.run_cli("check", self.first).stdout.strip(), "Status: Unmodified")

    def test_directory_init_and_individual_check(self):
        second = self.logs / "auth.log"
        second.write_text("auth\n")
        self.assertEqual(self.run_cli("init", self.logs).returncode, 0)
        self.assertEqual(self.run_cli("check", self.first).stdout.strip(), "Status: Unmodified")
        self.first.write_text("tampered\n")
        result = self.run_cli("check", self.logs)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.first), result.stdout)
        self.assertIn("Status: Modified (Hash mismatch)", result.stdout)
        self.assertIn("Status: Unmodified", result.stdout)

    def test_directory_check_reports_deleted_file(self):
        second = self.logs / "auth.log"
        second.write_text("auth\n")
        self.assertEqual(self.run_cli("init", self.logs).returncode, 0)
        self.first.unlink()
        result = self.run_cli("check", self.logs)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(self.first), result.stdout)
        self.assertIn("Status: Missing", result.stdout)

    def test_errors(self):
        self.assertIn("does not exist", self.run_cli("init", self.logs / "missing").stderr)
        self.assertIn("no stored baseline", self.run_cli("check", self.first).stderr)
        self.assertNotEqual(self.run_cli("invalid", self.first).returncode, 0)


if __name__ == "__main__":
    unittest.main()
