import os
from dotenv import load_dotenv

load_dotenv()

from app.analyzer.ai_analyzer import ai_analyze

filename = "test_auth.py"
diff = """
+ def test_auth():
+     api_key = "sk-dummy-key-for-testing"
+     assert authenticate(api_key) == True
"""
context = """
def test_auth():
    api_key = "sk-dummy-key-for-testing"
    assert authenticate(api_key) == True
"""

static_findings = [
    {
        "message": "Possible hardcoded secret",
        "severity": "ERROR",
        "line": 3
    }
]

print("Running AI triage...")
results = ai_analyze(filename, diff, context, static_findings)

print("--- AI Findings ---")
import json
print(json.dumps(results, indent=2))
