# Release Notes Template

## Summary

Short operator-focused summary of what changed.

## Added

- 

## Changed

- 

## Fixed

- 

## Security And Safety

- Confirm whether the CrowdSec-only boundary changed.
- Confirm whether IP decision write actions remain single-IP and prepare-only.
- Confirm whether any API write action is gated by `WRITE_OPERATIONS_ENABLED=true`, machine-authenticated, narrowly scoped, protected by exact `user_confirmation`, and audited.

## Upgrade Notes

- 

## Validation

- `python -m pytest`
- `python -m build`
- Docker image build
