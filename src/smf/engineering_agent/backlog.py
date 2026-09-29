from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .models import BacklogItem

_PROJECT_QUERY = r"""query($number:Int!,$after:String){
  viewer {
    projectV2(number:$number) {
      items(first:100,after:$after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          content {
            __typename
            ... on Issue { number title body }
            ... on DraftIssue { title body }
          }
          fieldValues(first:30) {
            nodes {
              ... on ProjectV2ItemFieldTextValue {
                text
                field { ... on ProjectV2FieldCommon { name } }
              }
              ... on ProjectV2ItemFieldSingleSelectValue {
                name
                field { ... on ProjectV2FieldCommon { name } }
              }
            }
          }
        }
      }
    }
  }
}"""


def _map_item(raw: dict[str, Any]) -> BacklogItem:
    content = raw.get("content") or {}
    return BacklogItem(
        key=str(raw.get("backlog Key") or raw.get("Backlog Key") or ""),
        title=str(raw.get("title") or ""),
        work_type=str(raw.get("work Type") or raw.get("Work Type") or ""),
        priority=str(raw.get("priority") or raw.get("Priority") or "P2"),
        readiness=str(raw.get("readiness") or raw.get("Readiness") or ""),
        status=str(raw.get("status") or ""),
        implementation_state=str(
            raw.get("implementation State") or raw.get("Implementation State") or ""
        ),
        parent=str(raw.get("parent") or ""),
        issue_number=content.get("number"),
        issue_body=str(content.get("body") or ""),
    )


def load_project_items(path: Path) -> tuple[BacklogItem, ...]:
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return tuple(item for raw in payload.get("items", []) if (item := _map_item(raw)).key)


def _field(fields: list[dict[str, Any]], name: str, value_key: str) -> str:
    for value in fields:
        if (value.get("field") or {}).get("name") == name:
            return str(value.get(value_key) or "")
    return ""


def load_live_project_items(project_number: int = 2) -> tuple[BacklogItem, ...]:
    raw_items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        command = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={_PROJECT_QUERY}",
            "-F",
            f"number={project_number}",
        ]
        if cursor:
            command.extend(["-f", f"after={cursor}"])
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        payload = json.loads(result.stdout)
        page = payload["data"]["viewer"]["projectV2"]["items"]
        for node in page["nodes"]:
            fields = node.get("fieldValues", {}).get("nodes", [])
            content = node.get("content") or {}
            raw_items.append(
                {
                    "backlog Key": _field(fields, "Backlog Key", "text"),
                    "title": content.get("title", ""),
                    "work Type": _field(fields, "Work Type", "name"),
                    "priority": _field(fields, "Priority", "name"),
                    "readiness": _field(fields, "Readiness", "name"),
                    "status": _field(fields, "Status", "name"),
                    "implementation State": _field(fields, "Implementation State", "name"),
                    "parent": _field(fields, "Parent", "text"),
                    "content": {
                        "number": content.get("number"),
                        "body": content.get("body", ""),
                    },
                }
            )
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]
    return tuple(item for raw in raw_items if (item := _map_item(raw)).key)
