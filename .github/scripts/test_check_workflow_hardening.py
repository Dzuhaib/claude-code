#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check_workflow_hardening.py").resolve()
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
CLAUDE_ACTION = "anthropics/claude-code-action@925afb53776cf1a2b738c6bdbed37b4d4000ef13"


class WorkflowHardeningCheckerTest(unittest.TestCase):
    def run_checker(self, workflow, policy=None):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "test.yml").write_text(
                textwrap.dedent(workflow), encoding="utf-8"
            )
            if policy is not None:
                (root / ".github" / "egress-firewall.yaml").write_text(
                    textwrap.dedent(policy), encoding="utf-8"
                )
            return subprocess.run(
                [sys.executable, str(CHECKER), str(root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

    def hardened_workflow(self, input_name="allowed_non_write_users", value=None):
        if value is None:
            value = "${{ vars.CLAUDE_ALLOWED_NON_WRITE_USERS }}"
        return f"""
        name: Test
        on: issues
        permissions:
          contents: read
        jobs:
          claude:
            runs-on: ubuntu-24.04-firewall
            timeout-minutes: 10
            steps:
              - uses: {CHECKOUT}
              - uses: {CLAUDE_ACTION}
                with:
                  {input_name}: {value}
                  claude_args: "--model claude-opus-4-6 --permission-mode auto --max-turns 20"
        """

    def test_accepts_hardened_workflow(self):
        result = self.run_checker(
            self.hardened_workflow(),
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("checked 1 job", result.stdout)

    def test_rejects_unpinned_action(self):
        result = self.run_checker(
            """\
            name: Test
            on: issues
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
            """
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("not pinned to a commit SHA", result.stdout)

    def test_rejects_wildcard_non_write_users(self):
        result = self.run_checker(
            self.hardened_workflow("allowed_non_write_users", '"*"'),
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("allowed_non_write_users", result.stdout)

    def test_rejects_wildcard_allowed_bots(self):
        result = self.run_checker(
            self.hardened_workflow("allowed_bots", '"*"'),
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("allowed_bots", result.stdout)

    def test_rejects_wildcard_policy_host(self):
        result = self.run_checker(
            self.hardened_workflow(),
            """\
            mode: enforce
            allow:
              - "*.example.com"
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("contains '*'", result.stdout)

    def test_rejects_old_permission_mode(self):
        result = self.run_checker(
            self.hardened_workflow().replace("--permission-mode auto", "--permission-mode acceptEdits"),
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--permission-mode acceptEdits", result.stdout)

    def test_rejects_missing_cost_guards(self):
        workflow = self.hardened_workflow().replace(
            "            timeout-minutes: 10\n", ""
        ).replace(" --max-turns 20", "")
        result = self.run_checker(
            workflow,
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("timeout-minutes", result.stdout)
        self.assertIn("--max-turns", result.stdout)

    def test_rejects_excessive_cost_guards(self):
        workflow = self.hardened_workflow().replace(
            "timeout-minutes: 10", "timeout-minutes: 31"
        ).replace("--max-turns 20", "--max-turns 51")
        result = self.run_checker(
            workflow,
            """\
            mode: enforce
            allow:
              - api.anthropic.com
            """,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("timeout-minutes", result.stdout)
        self.assertIn("--max-turns 51", result.stdout)


if __name__ == "__main__":
    unittest.main()
