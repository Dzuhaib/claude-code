#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SAFE_ENV = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "SHELL",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "CLAUDE_PLUGIN_ROOT",
    "CLAUDE_PROJECT_DIR",
    "CLAUDE_SESSION_ID",
    "CLAUDE_HOOK_EVENT",
    "CLAUDE_TRANSCRIPT_PATH",
    "CLAUDE_FILE_PATH",
    "CLAUDE_TOOL_NAME",
}


def build_env(allow_env):
    env = {}
    for name in SAFE_ENV:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    for name in allow_env:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    return env


def isolation_prefix(command, cwd, writable_paths):
    bwrap = shutil.which("bwrap")
    if bwrap:
        prefix = [
            bwrap,
            "--unshare-net",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--chdir",
            str(Path(cwd).resolve()),
        ]
        for path in writable_paths:
            resolved = str(Path(path).resolve())
            prefix += ["--bind", resolved, resolved]
        return prefix + ["--"] + list(command), "bwrap"

    unshare = shutil.which("unshare")
    if unshare:
        return [unshare, "--net", "--"] + list(command), "unshare"

    raise RuntimeError("network isolation requires bwrap or unshare on Linux")


def command_digest(command):
    digest = hashlib.sha256()
    for part in command:
        digest.update(part.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
    return digest.hexdigest()


def append_audit(path, event):
    if not path:
        return
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(audit_path.parent, 0o700)
    except OSError:
        pass
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_APPEND
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(audit_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (AttributeError, OSError):
        pass
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def run_hook(
    command,
    *,
    cwd=None,
    timeout=60,
    audit_log=None,
    allow_env=(),
    isolate_network=False,
    writable_paths=(),
):
    if not command:
        raise ValueError("command is required")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    cwd = str(Path(cwd or os.getcwd()).resolve())
    env = build_env(list(allow_env))
    invoked = list(command)
    sandbox = "none"
    if isolate_network:
        invoked, sandbox = isolation_prefix(invoked, cwd, writable_paths)

    started = time.monotonic()
    exit_code = 1
    error = None
    try:
        completed = subprocess.run(
            invoked,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
        exit_code = completed.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124
        error = "timeout"
    except FileNotFoundError as exception:
        exit_code = 127
        error = str(exception)
    except OSError as exception:
        exit_code = 126
        error = str(exception)

    duration_ms = int((time.monotonic() - started) * 1000)
    append_audit(
        audit_log,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "hook_run",
            "command": Path(command[0]).name,
            "command_sha256": command_digest(list(command)),
            "cwd": cwd,
            "sandbox": sandbox,
            "isolate_network": bool(isolate_network),
            "allow_env": sorted(set(allow_env)),
            "timeout_seconds": timeout,
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "error": error,
        },
    )
    if error:
        print(f"hook_sandbox: {error}", file=sys.stderr)
    return exit_code


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run a Claude Code hook with a scrubbed environment and audit log."
    )
    parser.add_argument("--cwd")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--audit-log")
    parser.add_argument("--allow-env", action="append", default=[])
    parser.add_argument("--isolate-network", action="store_true")
    parser.add_argument("--writable", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("hook_sandbox: no command given", file=sys.stderr)
        return 2
    try:
        return run_hook(
            command,
            cwd=args.cwd,
            timeout=args.timeout,
            audit_log=args.audit_log,
            allow_env=args.allow_env,
            isolate_network=args.isolate_network,
            writable_paths=args.writable,
        )
    except (RuntimeError, ValueError) as error:
        print(f"hook_sandbox: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
