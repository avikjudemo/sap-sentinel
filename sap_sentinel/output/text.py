from __future__ import annotations

from typing import Iterable

from sap_sentinel.models import Finding


def emit_text(findings: list[Finding]) -> str:
    """
    Human-readable output.
    Example line:
      HIGH SAP001 destinations/ERP.json:12 Hardcoded destination credentials
    """
    if not findings:
        return "SAP Sentinel: no findings\n"

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in by_sev:
            by_sev[f.severity] += 1

    lines: list[str] = []
    lines.append("SAP Sentinel: findings detected")
    lines.append(
        f"Summary: critical={by_sev['critical']} high={by_sev['high']} "
        f"medium={by_sev['medium']} low={by_sev['low']} total={len(findings)}"
    )
    lines.append("")

    for f in findings:
        sev = f.severity.upper()
        lines.append(f"{sev} {f.rule_id} {f.path}:{f.line} {f.title}")

    lines.append("")
    return "\n".join(lines)
