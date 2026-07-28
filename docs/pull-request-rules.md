# Pull Request Rules

Every PR must keep the project boundary clear: this MCP only accesses CrowdSec.

## Required Checks

- CI must pass.
- Tests must pass.
- Python package build must pass.
- Docker build must pass when container files or dependencies change.

## Required PR Content

- Use the pull request template.
- Set a PR type: Feature, Fix, Chore, Docs, CI/CD, or Release.
- Include release-note text when the change is user-visible.
- Include a Safety section when the change affects the MCP tool contract, credentials, network access, deployment permissions, or write-action behavior.
- Dependabot dependency PRs are exempt from the manual PR template requirement.

## Safety Rules

- Do not add direct access to VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxies, or Docker.
- Do not add bulk ban, bulk unban, delete-all, or broad mutation tools.
- Keep write actions single-IP and dry-run by default.
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
