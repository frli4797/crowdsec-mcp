from importlib import util
from pathlib import Path


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_pr_metadata.py"
_SPEC = util.spec_from_file_location("validate_pr_metadata", _SCRIPT_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
validate_pr_metadata = util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validate_pr_metadata)


def _run_validator(monkeypatch, title, body):
    monkeypatch.setenv("PR_TITLE", title)
    monkeypatch.setenv("PR_BODY", body)
    return validate_pr_metadata.main()


def test_pr_metadata_allows_minimal_required_sections(monkeypatch):
    body = "\n".join(
        [
            "## Summary",
            "Relax PR metadata requirements.",
            "## Type",
            "Chore",
            "## Validation",
            "`pytest`",
        ]
    )

    assert _run_validator(monkeypatch, "Chore: relax pr metadata rules", body) == 0


def test_pr_metadata_does_not_require_safety_or_release_notes(monkeypatch):
    body = "\n".join(
        [
            "## Summary",
            "Docs-only change.",
            "## Type",
            "Docs",
            "## Validation",
            "Reviewed markdown.",
        ]
    )

    assert _run_validator(monkeypatch, "Docs: clarify onboarding", body) == 0


def test_pr_metadata_rejects_empty_release_notes_when_section_is_present(monkeypatch):
    body = "\n".join(
        [
            "## Summary",
            "User-visible change.",
            "## Type",
            "Feature",
            "## Validation",
            "`pytest`",
            "## Release Notes",
            "<!-- fill me -->",
        ]
    )

    assert _run_validator(monkeypatch, "Feature: add operator workflow", body) == 1
