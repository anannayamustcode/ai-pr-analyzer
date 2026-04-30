SEVERITY_ALIASES = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
}
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def normalize_finding(finding: dict) -> dict:
    issue = finding.get("issue") or finding.get("message") or ""
    message = finding.get("message") or issue
    severity = str(finding.get("severity", "LOW")).upper()
    severity = SEVERITY_ALIASES.get(severity, severity)

    if severity not in ORDER:
        severity = "LOW"

    line = finding.get("line", finding.get("line_hint", 1))
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 1

    line = max(line, 1)

    return {
        **finding,
        "issue": str(issue).strip(),
        "message": str(message).strip(),
        "severity": severity,
        "line": line,
        "line_hint": line,
    }


def merge_findings(static: list[dict], ai: list[dict]) -> list[dict]:
    seen = set()
    merged = []

    for finding in static + ai:
        normalized = normalize_finding(finding)
        key = (
            normalized.get("issue", ""),
            normalized.get("message", ""),
            normalized.get("severity", ""),
            normalized.get("line", ""),
        )

        if key in seen:
            continue

        seen.add(key)
        merged.append(normalized)

    return sorted(merged, key=lambda item: ORDER.get(item.get("severity", "LOW").upper(), 3))


def score(findings: list[dict]) -> int:
    normalized = [normalize_finding(finding) for finding in findings]
    high = sum(1 for finding in normalized if finding.get("severity") == "HIGH")
    medium = sum(1 for finding in normalized if finding.get("severity") == "MEDIUM")
    low = sum(1 for finding in normalized if finding.get("severity") == "LOW")
    raw = high * 15 + medium * 7 + low * 2
    return max(0, 100 - raw)


def format_summary(findings: list[dict], security_score: int) -> str:
    sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    normalized = [normalize_finding(finding) for finding in findings]
    lines = [
        "## Security Scan Results",
        "",
        f"**Security Score: {security_score}/100**",
        "",
    ]

    if not normalized:
        lines.append("No issues found.")
    else:
        for finding in normalized:
            severity = finding.get("severity", "LOW").upper()
            icon = sev_icon.get(severity, "⚪")
            issue = finding.get("issue") or finding.get("message")
            line = finding.get("line_hint") or finding.get("line")

            lines.append(f"{icon} **{severity}** - {issue} (line {line})")

            if finding.get("explanation"):
                lines.append(f"   *Why:* {finding['explanation']}")

            if finding.get("fix"):
                lines.append(f"   *Fix:* {finding['fix']}")

    return "\n".join(lines)
