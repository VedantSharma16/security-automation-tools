import os
import tempfile
import unittest

from log_triage_agent.cli import main


class TestCliIntegration(unittest.TestCase):
    def test_end_to_end_report_generation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = os.path.join(tmp_dir, "report.md")
            exit_code = main(
                ["--log", "data/sample_auth.log", "--year", "2026", "--out", out_path]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, encoding="utf-8") as f:
                report = f.read()

            self.assertIn("Brute Force", report)
            self.assertIn("Password Spray", report)
            self.assertIn("Credential Success After Failures", report)
            self.assertIn("Off Hours Login", report)

    def test_missing_log_file_returns_error_code(self):
        exit_code = main(["--log", "data/does_not_exist.log"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
