import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hook_sandbox


class HookSandboxTest(unittest.TestCase):
    def test_scrubs_secret_environment_by_default(self):
        with mock.patch.dict(os.environ, {"SECRET_TOKEN": "secret"}, clear=False):
            env = hook_sandbox.build_env([])
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertIn("PATH", env)

    def test_allows_explicit_environment(self):
        with mock.patch.dict(os.environ, {"SECRET_TOKEN": "secret"}, clear=False):
            env = hook_sandbox.build_env(["SECRET_TOKEN"])
        self.assertEqual(env["SECRET_TOKEN"], "secret")

    def test_timeout_returns_124(self):
        code = hook_sandbox.run_hook(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout=0.2,
        )
        self.assertEqual(code, 124)

    def test_missing_command_returns_127(self):
        code = hook_sandbox.run_hook(["definitely-not-a-real-command"])
        self.assertEqual(code, 127)

    def test_writes_jsonl_audit_log(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            audit_log = Path(temporary_directory) / "audit" / "hooks.jsonl"
            code = hook_sandbox.run_hook(
                [sys.executable, "-c", "pass"],
                audit_log=audit_log,
            )
            self.assertEqual(code, 0)
            event = json.loads(audit_log.read_text(encoding="utf-8").strip())
        self.assertEqual(event["event"], "hook_run")
        self.assertEqual(event["exit_code"], 0)
        self.assertEqual(event["sandbox"], "none")
        self.assertIn("command_sha256", event)
        self.assertNotIn("secret", json.dumps(event))

    def test_rejects_empty_command(self):
        with self.assertRaisesRegex(ValueError, "command is required"):
            hook_sandbox.run_hook([])

    def test_rejects_nonpositive_timeout(self):
        with self.assertRaisesRegex(ValueError, "timeout must be positive"):
            hook_sandbox.run_hook(["python"], timeout=0)

    def test_isolation_requires_a_sandbox_tool(self):
        with mock.patch("hook_sandbox.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "bwrap or unshare"):
                hook_sandbox.isolation_prefix(["python"], ".", [])

    def test_bubblewrap_isolation_prefix(self):
        def which(name):
            return "/usr/bin/bwrap" if name == "bwrap" else None

        with mock.patch("hook_sandbox.shutil.which", side_effect=which):
            command, sandbox = hook_sandbox.isolation_prefix(["python"], ".", [])
        self.assertEqual(sandbox, "bwrap")
        self.assertIn("--unshare-net", command)
        self.assertIn("--ro-bind", command)

    def test_unshare_isolation_prefix(self):
        def which(name):
            return "/usr/bin/unshare" if name == "unshare" else None

        with mock.patch("hook_sandbox.shutil.which", side_effect=which):
            command, sandbox = hook_sandbox.isolation_prefix(["python"], ".", [])
        self.assertEqual(sandbox, "unshare")
        self.assertIn("--net", command)


if __name__ == "__main__":
    unittest.main()
