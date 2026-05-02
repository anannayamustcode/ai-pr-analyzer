import time
import jwt
import requests
from app.utils.config import GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH

def get_jwt_token():
    with open(GITHUB_PRIVATE_KEY_PATH, "r") as f:
        private_key = f.read()

    now = int(time.time())

    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": GITHUB_APP_ID
    }

    return jwt.encode(payload, private_key, algorithm="RS256")


def get_installation_token(installation_id):
    jwt_token = get_jwt_token()

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json"
        }
    )

    response.raise_for_status()
    return response.json()["token"]


def get_pr_files(repo, pr_number, token):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"

    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
    )

    response.raise_for_status()
    return response.json()


def post_pr_comment(repo, pr_number, token, body):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
    )

    response.raise_for_status()
    return response.json()


def post_pr_inline_comment(repo, pr_number, token, body, path, line, commit_id):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"

    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "body": body,
            "path": path,
            "line": line,
            "side": "RIGHT",
            "commit_id": commit_id,
        },
    )

    response.raise_for_status()
    return response.json()
