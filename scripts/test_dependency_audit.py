import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dependency_audit

PINNED_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
PINNED_IMAGE = "node@sha256:" + "a" * 64


class DependencyAuditTest(unittest.TestCase):
    def make_repo(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        (root / ".github" / "workflows").mkdir(parents=True)
        return root

    def write(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_accepts_immutable_references(self):
        root = self.make_repo()
        self.write(
            root / ".github" / "workflows" / "test.yml",
            f"steps:\n  - uses: {PINNED_ACTION}\n",
        )
        self.write(root / "Dockerfile", f"FROM {PINNED_IMAGE}\n")
        self.write(root / "requirements.txt", "cryptography==50.0.2\n")
        findings, inventory = dependency_audit.audit(root)
        self.assertEqual(findings, [])
        self.assertEqual(len(inventory["actions"]), 1)
        self.assertEqual(len(inventory["images"]), 1)

    def test_rejects_mutable_references(self):
        root = self.make_repo()
        self.write(
            root / ".github" / "workflows" / "test.yml",
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - run: pip install requests\n"
            "  - run: npm install -g typescript\n",
        )
        self.write(root / "Dockerfile", "FROM node:20\n")
        self.write(root / "requirements.txt", "flask>=3\n")
        findings, _ = dependency_audit.audit(root)
        text = "\n".join(findings)
        self.assertIn("not pinned to a full commit SHA", text)
        self.assertIn("pip package 'requests'", text)
        self.assertIn("npm package 'typescript'", text)
        self.assertIn("base image 'node:20'", text)
        self.assertIn("flask>=3", text)

    def test_skips_requirement_files_in_install_commands(self):
        root = self.make_repo()
        self.write(
            root / ".github" / "workflows" / "test.yml",
            "run: python3 -m pip install -r requirements.txt\n",
        )
        self.write(root / "requirements.txt", "cryptography==50.0.2\n")
        findings, _ = dependency_audit.audit(root)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
