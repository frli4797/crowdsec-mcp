from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path


MARKER = "<!-- crowdsec-mcp-agentic-review -->"
MAX_DIFF_CHARS = 60000


def main() -> int:
    event = _load_event()
    pr = event.get("pull_request") or {}
    if not pr:
        _emit("Agentic review skipped: no pull request event found.")
        return 0
    pr_number = pr.get("number")
    base_ref = pr.get("base", {}).get("ref", "main")
    head_sha = pr.get("head", {}).get("sha", "HEAD")
    api_key = os.getenv("OPENAI_API_KEY")

    diff = _git_diff(base_ref)
    if not diff.strip():
        _emit("Agentic review skipped: no diff found.")
        return 0

    if not api_key:
        _emit("Agentic review skipped: `OPENAI_API_KEY` is not configured for this workflow.")
        return 0

    model = os.getenv("AGENTIC_REVIEW_MODEL") or "gpt-5.6-luna"
    prompt = _build_prompt(diff, pr, head_sha)

    try:
        review = _openai_review(api_key, model, prompt)
    except Exception as exc:  # noqa: BLE001 - advisory workflow must not block PRs.
        _emit(f"Agentic review could not run: {exc}")
        return 0

    body = f"{MARKER}\n## Agentic review\n\n{review.strip()}\n"
    _emit(body)

    if pr_number and os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPOSITORY"):
        try:
            _upsert_pr_comment(int(pr_number), body)
        except Exception as exc:  # noqa: BLE001 - comments are best-effort.
            _emit(f"\nComment update skipped: {exc}")

    return 0


def _load_event() -> dict:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    path = Path(event_path)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _git_diff(base_ref: str) -> str:
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", base_ref], check=False)
    candidates = [f"origin/{base_ref}...HEAD", f"origin/{base_ref}..HEAD"]
    for revision in candidates:
        result = subprocess.run(
            ["git", "diff", "--unified=80", "--no-ext-diff", revision],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            diff = result.stdout
            if len(diff) > MAX_DIFF_CHARS:
                diff = diff[:MAX_DIFF_CHARS] + "\n\n[Diff truncated for advisory review.]\n"
            return diff
    return ""


def _build_prompt(diff: str, pr: dict, head_sha: str) -> str:
    title = pr.get("title") or "(untitled)"
    body = pr.get("body") or ""
    return textwrap.dedent(
        f"""
        You are performing an advisory code review for crowdsec-ops-mcp.

        Project constraints:
        - CrowdSec-only MCP server.
        - Do not recommend direct VictoriaMetrics, VictoriaLogs, Grafana, Snort, reverse proxy, Docker socket, or Docker API integrations.
        - Write tools must remain prepare-only, audited, and single-IP scoped.
        - Actual cscli reads or execution are not supported.
        - Focus on correctness, safety, security, regression risk, and missing tests.

        This review is advisory and must not approve or block the PR. Return:
        - "Blocking concerns: none" when no serious issue is found.
        - Concise findings with file paths when there are risks.
        - A short test/verification note.

        PR title: {title}
        PR head SHA: {head_sha}

        PR body:
        {body}

        Diff:
        {diff}
        """
    ).strip()


def _openai_review(api_key: str, model: str, prompt: str) -> str:
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(
            {
                "model": model,
                "input": prompt,
                "text": {"verbosity": "medium"},
            }
        ).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"OpenAI API returned HTTP {exc.code}: {detail[:500]}") from exc

    output_text = payload.get("output_text")
    if output_text:
        return str(output_text)

    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                chunks.append(str(content["text"]))
    if chunks:
        return "\n".join(chunks)
    return "Blocking concerns: none\n\nNo text output was returned by the model."


def _upsert_pr_comment(pr_number: int, body: str) -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    comments = _github_request("GET", comments_url, token)
    for comment in comments:
        if MARKER in comment.get("body", ""):
            _github_request("PATCH", comment["url"], token, {"body": body})
            return
    _github_request("POST", comments_url, token, {"body": body})


def _github_request(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode()
        return json.loads(raw) if raw else None


def _emit(message: str) -> None:
    print(message)
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(message)
            summary.write("\n")


if __name__ == "__main__":
    sys.exit(main())
