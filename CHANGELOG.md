# Version History

## Unreleased

- Nothing yet.

## v0.3.1 - 2026-08-13

### Changed

- Upgraded direct GitHub Actions cache usage to `actions/cache@v5` for Node.js 24 compatibility.
- Hardened Python virtualenv cache keys with the resolved Python patch version.
- Split Docker dependency installation from source installation so code-only image builds can reuse dependency layers across architectures.

### Security And Safety

- CrowdSec-only MCP boundary is unchanged.
- Write actions remain prepare-only, with no MCP-executed CrowdSec mutations.
- No MCP-executed CrowdSec mutations are introduced.

## v0.3.0 - 2026-08-13

### Added

- Added `decision_gap_report(...)`, a read-only report for repeated alerts without active decisions, stale decisions, expiring decisions with recent alerts, noisy scenarios, and repeat offenders below threshold.
- Added example `decision_gap_report` documentation.
- Added Snort-derived CrowdSec parser, scenario, notification, and profile-snippet examples for operator-reviewed deployments outside the MCP.
- Added a target-host installer script for pulling the Snort/CrowdSec examples from a raw Git repository URL.
- Added optional advisory agentic PR review workflow support.

### Changed

- Updated roadmap and README documentation to include `decision_gap_report`.
- Documented issue-first contribution expectations and advisory code-review behavior.
- Kept Snort, VictoriaMetrics, and notification examples explicitly outside the MCP runtime integration boundary.

### Security And Safety

- CrowdSec-only MCP boundary is unchanged.
- Write actions remain single-IP, prepare-only, and audited.
- No MCP-executed CrowdSec mutations are introduced.
- New scenario/profile examples are deployment artifacts for operator review; the MCP does not install, reload, or mutate CrowdSec configuration.

## v0.2.1 - 2026-07-28

### Changed

- Cached the GitHub Actions Python virtualenv in CI and release validation jobs.
- Reused the cached build environment with `python -m build --no-isolation`.

### Security And Safety

- Runtime behavior is unchanged.
- CrowdSec-only boundary is unchanged.
- Write actions remain single-IP, prepare-only, and audited.

## v0.2.0 - 2026-07-28

### Added

- Added `crowdsec_health(include_sample_counts=false)` for read-only backend health, configuration presence, and capability reporting without exposing secrets.
- Added `decision_inventory(...)` for grouped active-decision inventory, filters, expiring-soon decisions, stale or long-lived decisions, and representative rows.
- Added a decision inventory example guide.
- Added a project roadmap.
- Added `AGENTS.md`, agent usage guidance, and development workflow documentation.
- Added README contents and a fuller project document index.
- Added worktree bootstrap support for local runtime files.

### Changed

- Reorganized documentation so README and onboarding stay user-facing while agent, development, release, and roadmap content live in dedicated files.
- Clarified the project roadmap around read-side investigation tools, write-operation planning, and shared reliability work.
- Relaxed PR metadata validation rules for dependency updates.

### Fixed

- Made IP write tools prepare-only even when an `execute` flag is supplied.
- Improved MCP logging and CrowdSec client error handling.
- Ignored local compose and audit files.

### Security And Safety

- CrowdSec remains the only direct integration boundary.
- Write tools remain single-IP, prepare-only, and audited.
- No MCP-executed CrowdSec mutations are introduced.

## v0.1.1 - 2026-07-28

- Updated CI and container publishing for multi-architecture GHCR images.
- Documented private GHCR pulls.

## v0.1.0 - 2026-07-28

- Initial tagged release using the published container image workflow.
