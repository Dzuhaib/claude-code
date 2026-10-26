#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

ACTION_PIN = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
DOCKER_DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-fA-F]{64}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)")
FROM = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)
PIP_INSTALL = re.compile(r"\bpip3?\s+install\b(.+)")
NPM_INSTALL = re.compile(r"\bnpm\s+install\s+-g\s+(.+)")
SKIP_PARTS = {".git", "node_modules", "vendor", "dist", "build"}


def workflow_files(root):
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    return sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])


def dockerfiles(root):
    found = set()
    for pattern in ("Dockerfile", "Dockerfile.*", "*.Dockerfile"):
        for path in root.rglob(pattern):
            if path.is_file() and not any(part in SKIP_PARTS for part in path.parts):
                found.add(path)
    return sorted(found)


def requirement_files(root):
    return sorted(
        path
        for path in root.rglob("requirements*.txt")
        if path.is_file() and not any(part in SKIP_PARTS for part in path.parts)
    )


def package_names(text):
    names = []
    for token in text.split():
        if token.startswith("-") or token in ("&&", "||"):
            continue
        if token.startswith("#"):
            break
        names.append(token.strip("'\""))
    return names


def check_action(where, reference, findings, inventory):
    if reference.startswith("./"):
        return
    inventory["actions"].append({"where": where, "reference": reference})
    if reference.startswith("docker://"):
        if not DOCKER_DIGEST.match(reference[9:]):
            findings.append(
                f"{where}: Docker action '{reference}' is not pinned by digest"
            )
        return
    if not ACTION_PIN.match(reference):
        findings.append(
            f"{where}: action '{reference}' is not pinned to a full commit SHA"
        )


def check_pip(where, arguments, findings, inventory):
    if re.search(r"(?:^|\s)(?:-r|--requirement)(?:\s|=)", arguments):
        return
    packages = package_names(arguments)
    if not packages:
        return
    for package in packages:
        if package.startswith("-"):
            continue
        inventory["pip"].append({"where": where, "package": package})
        if "==" not in package and " @ " not in package:
            findings.append(
                f"{where}: pip package '{package}' is not pinned with '==' or a URL hash"
            )


def check_npm(where, arguments, findings, inventory):
    packages = package_names(arguments)
    for package in packages:
        inventory["npm"].append({"where": where, "package": package})
        if package.startswith("@"):
            name, _, version = package.rpartition("@")
            if not name or not version:
                findings.append(
                    f"{where}: npm package '{package}' is not pinned to a version"
                )
            continue
        if "@" not in package:
            findings.append(
                f"{where}: npm package '{package}' is not pinned to a version"
            )


def scan_workflow(path, root, findings, inventory):
    where_base = path.relative_to(root).as_posix()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        where = f"{where_base}:{line_number}"
        match = USES.search(line)
        if match:
            check_action(where, match.group(1), findings, inventory)
        match = PIP_INSTALL.search(line)
        if match:
            check_pip(where, match.group(1), findings, inventory)
        match = NPM_INSTALL.search(line)
        if match:
            check_npm(where, match.group(1), findings, inventory)


def scan_dockerfile(path, root, findings, inventory):
    where_base = path.relative_to(root).as_posix()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = FROM.match(line)
        if not match:
            continue
        image = match.group(1)
        if image.lower() == "scratch" or image.startswith("${"):
            continue
        where = f"{where_base}:{line_number}"
        inventory["images"].append({"where": where, "image": image})
        if not DOCKER_DIGEST.match(image):
            findings.append(f"{where}: base image '{image}' is not pinned by digest")


def scan_requirements(path, root, findings, inventory):
    where_base = path.relative_to(root).as_posix()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#") or text.startswith("-"):
            continue
        where = f"{where_base}:{line_number}"
        inventory["pip"].append({"where": where, "package": text})
        if "==" not in text and " @ " not in text:
            findings.append(
                f"{where}: Python dependency '{text}' is not pinned with '==' or a URL hash"
            )


def audit(root):
    findings = []
    inventory = {"actions": [], "images": [], "pip": [], "npm": []}
    for path in workflow_files(root):
        scan_workflow(path, root, findings, inventory)
    for path in dockerfiles(root):
        scan_dockerfile(path, root, findings, inventory)
    for path in requirement_files(root):
        scan_requirements(path, root, findings, inventory)
    return findings, inventory


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit action, image, and package references for mutable pins."
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    findings, inventory = audit(root)
    if args.json:
        print(json.dumps({"findings": findings, "inventory": inventory}, indent=2))
    elif findings:
        for finding in findings:
            print(f"ERROR: {finding}", file=sys.stderr)
    else:
        print("OK: all discovered dependencies are pinned to immutable references.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
