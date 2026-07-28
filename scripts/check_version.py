from __future__ import annotations

import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_version.py <tag>", file=sys.stderr)
        return 2

    tag = sys.argv[1]
    if not tag.startswith("v"):
        print(f"release tag must start with v: {tag}", file=sys.stderr)
        return 1

    expected = tag[1:]
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    package_version = pyproject["project"]["version"]
    init_text = (ROOT / "src" / "crowdsec_ops_mcp" / "__init__.py").read_text()
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    init_version = match.group(1) if match else None

    failures = []
    if package_version != expected:
        failures.append(f"pyproject.toml has {package_version}, expected {expected}")
    if init_version != expected:
        failures.append(f"__init__.py has {init_version}, expected {expected}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"version ok: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
