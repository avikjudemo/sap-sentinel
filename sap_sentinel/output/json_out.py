from __future__ import annotations

import json
from typing import Any

from sap_sentinel.models import Finding
from sap_sentinel.scripts import build_json_report


def emit_json(
    findings: list[Finding],
    *,
    tool_version: str,
    root: str,
    fail_on: str,
    started_at: str,
    finished_at: str,
) -> str:
    """
    Machine-readable JSON report (your structure).
    """
    report: dict[str, Any] = build_json_report(
        findings,
        tool_version=tool_version,
        root=root,
        fail_on=fail_on,
        started_at=started_at,
        finished_at=finished_at,
    )
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
