# Security Policy
Thank you for helping us keep Claude Code secure!

## Reporting Security Issues

The security of our systems and user data is Anthropic's top priority. We appreciate the work of security researchers acting in good faith in identifying and reporting potential vulnerabilities.

Our security program is managed on HackerOne and we ask that any validated vulnerability in this functionality be reported through their [submission form](https://hackerone.com/4f1f16ba-10d3-4d09-9ecc-c721aad90f24/embedded_submissions/new).

## Repository Scope

This repository contains GitHub Actions workflows, plugins, hooks, deployment examples, and documentation. Reports about its source are in scope when they show a practical security impact, including:

- privilege escalation or secret exposure in workflows
- prompt injection that reaches a privileged workflow or tool
- unsafe command execution in hooks or plugin scripts
- gateway, devcontainer, or MDM examples that weaken security defaults
- mutable or unverified supply-chain references

The Claude Code CLI itself is distributed separately. Report vulnerabilities in the CLI through the same HackerOne program, and include the affected version. Use synthetic values in proofs of concept; never include real credentials.

## Anthropic Bug Bounty

Our Bug Bounty Program Guidelines are defined on our [HackerOne program page](https://hackerone.com/anthropic).
