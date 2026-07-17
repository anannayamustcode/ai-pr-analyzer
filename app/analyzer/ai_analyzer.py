import json
import os
import re

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


SYSTEM = """You are a senior security engineer and a strict triage system.
Your job is to evaluate static analysis (Semgrep) findings, filter out false positives, adjust severities based on context, generate fixes for true positives, and identify business logic flaws that Semgrep missed.
- If a finding is a false positive (e.g., hardcoded secret in a test file, or sanitized input), set "is_false_positive" to true.
- If a finding is a true positive but low risk in this context, downgrade its "severity" (HIGH|MEDIUM|LOW|INFO).
- Generate a concrete "fix" snippet for true positives.
- Return ONLY valid JSON, no markdown explanation text."""

USER_TEMPLATE = """File: {filename}

Surrounding context:
{context}

Diff (added lines):
{diff}

Static analysis findings (Semgrep):
{static_findings_json}

Return a JSON array of evaluated findings plus any new business logic flaws you found: 
[{{
    "issue": "description", 
    "severity": "HIGH|MEDIUM|LOW|INFO", 
    "line_hint": int, 
    "explanation": "Why this is a true positive or false positive", 
    "fix": "Suggested code fix if applicable",
    "is_false_positive": bool
}}]"""


def _strip_markdown_fences(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\s*```$", "", raw)
    return raw.strip()


def _normalize_findings(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    findings = []
    for item in value:
        if not isinstance(item, dict):
            continue

        issue = item.get("issue") or item.get("message")
        severity = item.get("severity", "MEDIUM")
        line = item.get("line_hint", item.get("line"))
        explanation = item.get("explanation", "")
        fix = item.get("fix", "")

        if not isinstance(issue, str) or not issue.strip():
            continue

        if severity not in {"HIGH", "MEDIUM", "LOW", "ERROR", "WARNING", "INFO"}:
            severity = "MEDIUM"

        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 1

        is_fp = item.get("is_false_positive")
        if isinstance(is_fp, str):
            is_fp = is_fp.lower() == "true"
        elif not isinstance(is_fp, bool):
            is_fp = False
            
        if is_fp:
            continue

        findings.append(
            {
                "issue": issue.strip(),
                "message": issue.strip(),
                "severity": severity,
                "line_hint": max(line, 1),
                "line": max(line, 1),
                "explanation": explanation if isinstance(explanation, str) else "",
                "fix": fix if isinstance(fix, str) else "",
            }
        )

    return findings


def _parse_ai_response(raw: str) -> list[dict]:
    raw = _strip_markdown_fences(raw)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []

    return _normalize_findings(parsed)


def ai_analyze(filename: str, diff: str, context: str = "", static_findings: list[dict] = None) -> list[dict]:
    if OpenAI is None:
        print("OpenAI package is not installed; skipping AI analysis")
        return []

    groq_key = os.getenv("GROQ_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    if not groq_key and not openai_key:
        print("Neither GROQ_API_KEY nor OPENAI_API_KEY is set; skipping AI analysis")
        return []

    if static_findings is None:
        static_findings = []

    if groq_key:
        client = OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1")
        model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    else:
        client = OpenAI(api_key=openai_key)
        model = os.getenv("OPENAI_MODEL", "gpt-4o")

    prompt = USER_TEMPLATE.format(
        filename=filename, 
        diff=diff, 
        context=context,
        static_findings_json=json.dumps(static_findings, indent=2)
    )

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
    except Exception as error:
        print(f"AI analysis failed: {error}")
        return static_findings

    raw = resp.choices[0].message.content or ""
    return _parse_ai_response(raw)
