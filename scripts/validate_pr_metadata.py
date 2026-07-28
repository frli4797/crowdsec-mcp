from __future__ import annotations

import os
import re
import sys


TITLE_RE = re.compile(r"^(Feature|Fix|Chore|Docs|CI/CD|Release): .+")
REQUIRED_SECTIONS = [
    "## Summary",
    "## Type",
    "## Safety",
    "## Validation",
    "## Release Notes",
]


def main() -> int:
    title = os.environ.get("PR_TITLE", "")
    body = os.environ.get("PR_BODY", "")
    errors: list[str] = []

    if title.startswith("build(deps"):
        print("Dependabot dependency PR metadata ok")
        return 0

    if not TITLE_RE.match(title):
        errors.append("PR title must match: Feature|Fix|Chore|Docs|CI/CD|Release: short summary")

    for section in REQUIRED_SECTIONS:
        if section not in body:
            errors.append(f"PR body is missing required section: {section}")

    if "## Release Notes" in body:
        release_notes = body.split("## Release Notes", 1)[1].strip()
        if not release_notes or release_notes.startswith("<!--"):
            errors.append('Release Notes must contain user-visible notes or "None".')

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("PR metadata ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
