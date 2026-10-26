#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
SKIP_PARTS = {".git", "build", "dist", "node_modules", "vendor"}
PATTERNS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]


def tracked_files():
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return [str(path) for path in Path(".").rglob("*") if path.is_file()]
    return [
        name
        for name in result.stdout.decode("utf-8", "surrogateescape").split("\0")
        if name
    ]


def is_skipped(path):
    return any(part in SKIP_PARTS for part in path.parts)


def scan_file(path):
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) > MAX_BYTES or b"\x00" in data:
        return []
    findings = []
    text = data.decode("utf-8", "ignore")
    for line_number, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((line_number, name))
                break
    return findings


def main():
    if len(sys.argv) > 1:
        os.chdir(sys.argv[1])
    findings = []
    for name in tracked_files():
        path = Path(name)
        if path.is_symlink() or not path.is_file() or is_skipped(path):
            continue
        for line_number, kind in scan_file(path):
            findings.append((name, line_number, kind))
    if not findings:
        print("OK: no high-confidence secrets found.")
        return 0
    print("Potential secrets found:", file=sys.stderr)
    for name, line_number, kind in findings:
        print(f"{name}:{line_number}: {kind}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
