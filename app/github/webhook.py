import hashlib
import hmac
import json
import os

from fastapi import APIRouter, HTTPException, Request

from app.analyzer.ai_analyzer import ai_analyze
from app.analyzer.diff_parser import diff_position_for_added_line, extract_added_lines
from app.analyzer.findings import format_summary, merge_findings, score
from app.analyzer.semgrep_runner import run_semgrep
from app.github.client import (
    get_installation_token,
    get_pr_files,
    post_pr_comment,
    post_pr_inline_comment,
)


router = APIRouter()


def verify_signature(body: bytes, signature: str):
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

    expected = "sha256=" + hmac.new(
        secret, body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


def _inline_comment_body(issue: dict) -> str:
    body = issue["message"]

    if issue.get("explanation"):
        body = f"{body}\n\nWhy: {issue['explanation']}"

    if issue.get("fix"):
        body = f"{body}\n\nFix: {issue['fix']}"

    return body


def _post_inline_comments(repo, pr_number, token, commit_id, filename, patch, findings):
    for issue in findings:
        print(f"WARNING [{issue['severity']}] {issue['message']} (line {issue['line']})")

        if issue["severity"] == "INFO":
            continue

        position = diff_position_for_added_line(patch, issue["line"])
        if position is None:
            print(f"Could not map finding to diff position: {filename}:{issue['line']}")
            continue

        try:
            post_pr_inline_comment(
                repo=repo,
                pr_number=pr_number,
                token=token,
                body=_inline_comment_body(issue),
                path=filename,
                position=position,
                commit_id=commit_id,
            )
            print(f"Posted inline comment on {filename} at diff position {position}")
        except Exception as error:
            print(f"Failed to post inline comment on {filename}:{issue['line']}: {error}")


@router.post("/webhook")
async def webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    verify_signature(body, signature)

    payload = json.loads(body)

    action = payload.get("action")
    print("Webhook received:", action)

    if action in ["opened", "synchronize"]:
        repo = payload["repository"]["full_name"]
        pr_number = payload["pull_request"]["number"]
        commit_id = payload["pull_request"]["head"]["sha"]
        installation_id = payload["installation"]["id"]

        print(payload)
        print("Repo:", repo)
        print("PR Number:", pr_number)
        print("Installation ID:", installation_id)

        token = get_installation_token(installation_id)
        files = get_pr_files(repo, pr_number, token)

        print("\n--- ADDED LINES ---")
        pr_findings = []

        for f in files:
            filename = f["filename"]
            patch = f.get("patch", "")
            added_lines = extract_added_lines(patch)

            if not added_lines:
                continue

            code = "\n".join(added_lines)

            print(f"\nFile: {filename}")
            print("Code:\n", code)

            static_findings = run_semgrep(code, filename)
            ai_findings = ai_analyze(filename, code, context=patch)
            findings = merge_findings(static_findings, ai_findings)
            pr_findings.extend(findings)

            print(f"File security score: {score(findings)}/100")
            _post_inline_comments(repo, pr_number, token, commit_id, filename, patch, findings)

        pr_findings = merge_findings(pr_findings, [])
        security_score = score(pr_findings)
        print(f"\nOverall PR security score: {security_score}/100")

        summary = format_summary(pr_findings, security_score)
        try:
            post_pr_comment(repo, pr_number, token, summary)
            print("Posted security summary comment")
        except Exception as error:
            print(f"Failed to post security summary comment: {error}")

    return {"ok": True}
