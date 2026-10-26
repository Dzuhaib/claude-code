# CLAUDE.md

Guidance for Claude Code and other coding agents working in this repository.

## Security hardening for GitHub Actions

Workflow jobs in this repository that call Claude run with four protections.
Keep them when you add or edit a workflow.

1. **Egress-firewall runner.** The job has `runs-on: ubuntu-24.04-firewall`,
   a GitHub-hosted runner that filters the job's outbound network traffic. Do
   not move a job that calls Claude to another runner.
2. **Network allow list.** `.github/egress-firewall.yaml` lists the hosts
   those jobs may reach, besides any that GitHub's firewall allows by default.
   Keep `mode: enforce`, which is what makes the firewall block the rest. Follow
   that file's header when you add a host.
3. **Auto permission mode.** Every step that runs the Claude Code action
   (`uses: anthropics/claude-code-action`, or a local action with a
   `claude_args` input) passes `--permission-mode auto` in `claude_args`. A tool
   call that needs permission and that the allowed tools do not cover then runs
   only if Claude Code's safety review passes it. Allow only the tools the job
   needs, and keep any `--disallowedTools` list a step has. Use `claude-opus-4-6`
   or a newer model: on an older one Claude Code falls back to its default
   permission mode.
4. **Immutable actions.** Pin every remote action to a full commit SHA, and
   every Docker action to a digest. Put the tag in a comment so reviewers can
   see which release the SHA represents. Do not use branch or tag references.

`claude.yml` answers `@claude` mentions. The Claude Code action sets
`--permission-mode acceptEdits` for those, and the `--permission-mode auto` in
the workflow's `claude_args`, which comes after it, replaces it.

`.github/workflows/workflow-hardening.yml` runs a trusted checker from the base
branch and fails when any workflow uses a tag or branch instead of a commit SHA
or digest. It also fails when a job that runs the Claude Code action or mentions
`ANTHROPIC_FEDERATION_RULE_ID` breaks protection 1 or 3, or when the allow list
is missing, empty, not `mode: enforce`, or names a host with `*`. It also fails
on a literal `allowed_non_write_users: "*"` or `allowed_bots: "*"`, and when a
job that calls Claude lacks `timeout-minutes` or `--max-turns` within the
1-30 minute and 1-50 turn limits. It cannot see a job that calls
Claude another way, so check new workflows by hand too. If a job cannot meet protection 1 or 3, add it with the
reason to the matching exemption table in
`.github/scripts/check_workflow_hardening.py`. A job in `EXEMPT_FROM_AUTO_MODE`
must set no permission mode at all. Do not skip or weaken the check.

`allowed_non_write_users` is read from the repository variable
`CLAUDE_ALLOWED_NON_WRITE_USERS`, not hard-coded in a workflow. Keep that
variable empty unless a named list of trusted users is genuinely required; do
not set it to `*`. With the variable empty, the issue triage and dedupe jobs
still run for users who already have write access.

Keep each workflow's `permissions:` block minimal, and never print tokens or
environment variables in workflow logs.

`.github/dependabot.yml` proposes weekly updates for GitHub Actions, the Docker
images in `.devcontainer` and `examples/gateway/gcp`, and the Python signing
dependency in `scripts`. Review the diff before merging so a pinned reference
does not move to an unexpected release.

`.github/workflows/secret-scan.yml` runs
`.github/scripts/check_secrets.py` from the base branch against each pull
request's files. It reports only the path, line, and credential type; it never
prints the matching value. Add a pattern only when it is specific enough to
avoid false positives, and do not add allow-list entries for real credentials.

`.github/workflows/dependency-cve.yml` runs Trivy on a schedule and on changes
to the pinned Python signing dependency. `.github/workflows/security-tooling.yml`
tests plugin signing, the hook sandbox, dependency pin auditing, secret
redaction, and the security-guidance cost guard. AI workflows set
`timeout-minutes`, and the Claude steps set `--max-turns`, to bound cost.

Plugin releases can be signed with `scripts/plugin_signing.py`; private keys
must never be committed. `scripts/hook_sandbox.py` can impose a timeout,
scrubbed environment, optional Linux network isolation, and a JSONL audit log
on a hook command. `scripts/dependency_audit.py` rejects mutable action, image,
pip, and npm references. These tools reduce risk but do not make untrusted
plugin code safe; review plugin source before installation.
