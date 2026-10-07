"""Minimal Jira Cloud client (REST v3, basic auth with an API token). Blocking `requests` calls -
callers in async code wrap these in asyncio.to_thread so they never stall the event loop.
All four JIRA_* settings must be set, otherwise `configured()` is False and the platform falls
back to simulated tickets.
"""

import requests

from app.config import settings

TIMEOUT = 15

# Incident tier -> Jira priority name. Only sent if the project's create screen accepts it
# (see create_issue's fallback) - team-managed projects often don't expose the priority field.
PRIORITY = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}


class JiraError(Exception):
    pass


def configured() -> bool:
    return all([settings.jira_base_url, settings.jira_email, settings.jira_api_token, settings.jira_project_key])


def _base() -> str:
    return settings.jira_base_url.rstrip("/")


def _auth() -> tuple[str, str]:
    return (settings.jira_email, settings.jira_api_token)


def issue_url(key: str) -> str:
    return f"{_base()}/browse/{key}"


def _adf(lines: list[str]) -> dict:
    return {
        "type": "doc", "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in lines if line],
    }


def _error(resp: requests.Response) -> JiraError:
    try:
        body = resp.json()
        msg = "; ".join(body.get("errorMessages", []) + [f"{k}: {v}" for k, v in body.get("errors", {}).items()])
    except ValueError:
        msg = resp.text[:200]
    return JiraError(f"Jira returned {resp.status_code}: {msg or 'no detail'}")


def create_issue(
    summary: str, description_lines: list[str], labels: list[str], tier: str | None, priority_name: str | None = None,
) -> tuple[str, str]:
    """Creates a Task and returns (issue_key, browse_url). `priority_name` overrides the tier mapping."""
    fields = {
        "project": {"key": settings.jira_project_key},
        "issuetype": {"name": "Task"},
        "summary": summary[:250],
        "description": _adf(description_lines),
        "labels": [l.replace(" ", "-") for l in labels],
    }
    priority = priority_name or PRIORITY.get(tier or "")
    for attempt_fields in ([{**fields, "priority": {"name": priority}}] if priority else []) + [fields]:
        try:
            resp = requests.post(f"{_base()}/rest/api/3/issue", json={"fields": attempt_fields}, auth=_auth(), timeout=TIMEOUT)
        except requests.RequestException as e:
            raise JiraError(f"Could not reach Jira: {e}") from e
        if resp.status_code == 201:
            key = resp.json()["key"]
            return key, issue_url(key)
        if "priority" in attempt_fields and resp.status_code == 400 and "priority" in resp.text.lower():
            continue  # priority field not on this project's create screen - retry without it
        raise _error(resp)
    raise JiraError("Jira rejected the issue")


def get_status(key: str) -> tuple[str, str]:
    """Returns (status_name, status_category) where category is 'new' | 'indeterminate' | 'done'."""
    try:
        resp = requests.get(f"{_base()}/rest/api/3/issue/{key}", params={"fields": "status"}, auth=_auth(), timeout=TIMEOUT)
    except requests.RequestException as e:
        raise JiraError(f"Could not reach Jira: {e}") from e
    if resp.status_code == 404:
        return "Deleted in Jira", "done"
    if resp.status_code != 200:
        raise _error(resp)
    status = resp.json()["fields"]["status"]
    return status["name"], status["statusCategory"]["key"]


def _adf_text(node) -> str:
    """Flattens an Atlassian Document Format node to plain text (comments come back as ADF)."""
    if isinstance(node, dict):
        if node.get("type") == "text":
            return node.get("text", "")
        inner = "".join(_adf_text(c) for c in node.get("content", []))
        return inner + (chr(10) if node.get("type") in ("paragraph", "heading") else "")
    if isinstance(node, list):
        return "".join(_adf_text(c) for c in node)
    return ""


def get_details(key: str) -> dict:
    """Live issue details for the ticket card: status, assignee, priority, comments, status history."""
    try:
        resp = requests.get(
            f"{_base()}/rest/api/3/issue/{key}",
            params={"fields": "summary,status,assignee,priority,comment,created,updated", "expand": "changelog"},
            auth=_auth(), timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        raise JiraError(f"Could not reach Jira: {e}") from e
    if resp.status_code == 404:
        raise JiraError(f"{key} no longer exists in Jira")
    if resp.status_code != 200:
        raise _error(resp)
    data = resp.json()
    f = data["fields"]
    history = [
        {
            "at": h["created"], "by": (h.get("author") or {}).get("displayName", "Jira"),
            "from": item.get("fromString"), "to": item.get("toString"),
        }
        for h in data.get("changelog", {}).get("histories", [])
        for item in h.get("items", []) if item.get("field") == "status"
    ]
    return {
        "key": key, "summary": f.get("summary"), "url": issue_url(key),
        "status": f["status"]["name"], "status_category": f["status"]["statusCategory"]["key"],
        "assignee": (f.get("assignee") or {}).get("displayName"),
        "priority": (f.get("priority") or {}).get("name"),
        "created": f.get("created"), "updated": f.get("updated"),
        "comments": [
            {"author": c["author"]["displayName"], "at": c["created"], "body": _adf_text(c["body"]).strip()}
            for c in f.get("comment", {}).get("comments", [])
        ],
        "history": sorted(history, key=lambda h: h["at"]),
    }
