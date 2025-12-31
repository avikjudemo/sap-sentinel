from __future__ import annotations

import json
from typing import Any

from sap_sentinel.models import Finding


def _severity_to_sarif_level(severity: str) -> str:
    # SARIF levels: "error", "warning", "note", "none"
    s = severity.lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    if s == "low":
        return "note"
    return "warning"


def _dedupe_rules_from_findings(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    """
    SARIF requires declaring rules in tool.driver.rules.
    We build a minimal rules list from findings, keyed by ruleId.
    """
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id.lower(),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "help": {"text": f.description or "Review the finding and remediate."},
        }
    return rules


def emit_sarif(
    findings: list[Finding],
    *,
    tool_version: str,
) -> str:
    """
    SARIF v2.1.0 JSON output for GitHub Code Scanning ingestion.
    """
    rules_map = _dedupe_rules_from_findings(findings)
    rules_list = list(rules_map.values())

    results: list[dict[str, Any]] = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_sarif_level(f.severity),
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {
                                "startLine": max(1, int(f.line)),
                                "startColumn": max(1, int(f.column)),
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": f.fingerprint
                },
                "properties": {
                    "severity": f.severity,
                    "category": f.category,
                    "confidence": f.confidence,
                },
            }
        )

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sap-sentinel",
                        "version": tool_version,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
