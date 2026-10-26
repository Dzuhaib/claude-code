#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check_secrets.py").resolve()
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


class SecretCheckerTest(unittest.TestCase):
    def run_checker(self, content):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "sample.txt").write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

    def test_accepts_clean_file(self):
        result = self.run_checker("nothing sensitive here\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no high-confidence secrets", result.stdout)

    def test_rejects_aws_key(self):
        result = self.run_checker(f"key={AWS_KEY}\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("sample.txt:1: AWS access key", result.stderr)
        self.assertNotIn(AWS_KEY, result.stderr)

    def test_rejects_private_key(self):
        result = self.run_checker("-----BEGIN " + "PRIVATE KEY-----\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Private key", result.stderr)


if __name__ == "__main__":
    unittest.main()
