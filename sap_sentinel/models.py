
# #A single Finding object type used everywhere

# Simple severity comparisons (should_fail)

# A severity rank map for sorting and thresholds


from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Severity = Literal["low", "medium", "high", "critical"]

# Used for comparisons: higher number = more severe
SEVERITY_RANK: dict[str, int] = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

def is_valid_severity(value: str) -> bool:
    return value in SEVERITY_RANK


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity

    path: str
    line: int
    column: int

    snippet: str
    fingerprint: str

    description: Optional[str] = None
    confidence: Optional[str] = None  # e.g. "low"|"medium"|"high"
    category: Optional[str] = None    # e.g. "secrets"|"auth"|"tls"

    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    """
    Returns True if any finding has severity >= fail_on.
    fail_on can be: off|low|medium|high|critical
    """
    if fail_on == "off":
        return False
    if fail_on not in SEVERITY_RANK:
        raise ValueError(f"Invalid fail_on severity: {fail_on}")

    threshold = SEVERITY_RANK[fail_on]
    return any(f.severity_rank() >= threshold for f in findings)
