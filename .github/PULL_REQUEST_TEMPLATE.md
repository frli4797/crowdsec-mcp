## Summary

<!-- What changed and why? -->

## Type

<!-- Choose one: Feature, Fix, Chore, Docs, CI/CD, Release -->

## Safety

- [ ] This keeps the MCP CrowdSec-only.
- [ ] This does not add direct VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxy, or Docker socket access.
- [ ] IP decision write actions remain single-IP and prepare-only.
- [ ] Any API write action is gated by `WRITE_OPERATIONS_ENABLED=true`, machine-authenticated, narrowly scoped, protected by exact `user_confirmation`, and audited.

## Validation

- [ ] `python -m pytest`
- [ ] `python -m build`
- [ ] Docker build, if container behavior changed

## Release Notes

<!-- User-visible changes for the next release. Use "None" for internal-only changes. -->
