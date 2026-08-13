# Pull Request Rules

Every PR must keep the project boundary clear: this MCP only accesses CrowdSec.

## Required Checks

- CI must pass.
- Tests must pass.
- Python package build must pass.
- Docker build must pass when container files or dependencies change.
- Agentic review is optional and advisory; it must not be configured as a required check.

## Required PR Content

- Link an issue for non-trivial changes. The issue may be opened by the contributor.
- Use the pull request template.
- Set a PR type: Feature, Fix, Chore, Docs, CI/CD, or Release.
- Include release-note text when the change is user-visible.
- Include a Safety section when the change affects the MCP tool contract, credentials, network access, deployment permissions, or write-action behavior.
- Dependabot dependency PRs are exempt from the manual PR template requirement.

Small docs fixes, typo fixes, dependency updates, and obvious CI maintenance do not need a prior issue.

## Safety Rules

- Do not add direct access to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.
- Do not add bulk ban, bulk unban, delete-all, or broad mutation tools.
- Keep IP decision write tools single-IP and prepare-only; the MCP must not execute IP decision mutations.
- API write tools may execute only when they are narrow, gated by `WRITE_OPERATIONS_ENABLED=true`, machine-authenticated, and audited.
- Require an exact `user_confirmation` phrase for any executed API write tool.
- Keep scenario simulation writes single-scenario only.
- Prefer supported CrowdSec API-level access over remote `cscli` execution for new capabilities.
- Scenario, parser, and profile changes must be proposed, not applied automatically.

## Labeling

Use labels that feed generated release notes:

- `feature`
- `fix`
- `documentation`
- `ci`
- `release`
- `chore`
- `dependencies`
- `breaking-change`
- `ignore-for-release`

Use `agentic-review` only when an advisory model review is wanted for a PR. The workflow skips without that label, and it also skips if `OPENAI_API_KEY` is not configured.
