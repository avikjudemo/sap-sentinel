# scanner + orchestration scripts for SAP Sentinel.core backend functionality


from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sap_sentinel.models import Finding, SEVERITY_RANK, is_valid_severity


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".github",          # keep scanning app code, not workflows
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    "rules",        # excludes sap_sentinel/rules (self-scan protection)
    "output"        # excludes output emitters if desired
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_rules(rules_file: str | Path) -> list[dict[str, Any]]:
    """
    Loads rules from JSON file.
    Expected structure:
    {
      "rules": [
        {
          "id": "SAP001",
          "title": "...",
          "severity": "high",
          "category": "secrets",
          "description": "...",
          "confidence": "high",
          "file_globs": ["**/*.json", "destinations/*.json"],
          "patterns": ["regex1", "regex2"]
        }
      ]
    }
    """
    rules_path = Path(rules_file)
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    data = json.loads(rules_path.read_text(encoding="utf-8"))
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Rules file invalid: 'rules' must be a list")

    # validate minimally
    for r in rules:
        if "id" not in r or "title" not in r or "severity" not in r:
            raise ValueError(f"Rule missing required fields: {r}")
        if not is_valid_severity(r["severity"]):
            raise ValueError(f"Invalid severity in rule {r.get('id')}: {r['severity']}")
        if "file_globs" not in r or "patterns" not in r:
            raise ValueError(f"Rule {r.get('id')} must include file_globs and patterns")
        if not isinstance(r["file_globs"], list) or not isinstance(r["patterns"], list):
            raise ValueError(f"Rule {r.get('id')} file_globs/patterns must be lists")

    return rules


def is_excluded_dir(dir_name: str, extra_exclude: Iterable[str] | None = None) -> bool:
    if dir_name in DEFAULT_EXCLUDE_DIRS:
        return True
    if extra_exclude:
        return any(fnmatch.fnmatch(dir_name, pat) for pat in extra_exclude)
    return False


def is_probably_binary(sample: bytes) -> bool:
    # Simple heuristic: presence of NUL often indicates binary
    return b"\x00" in sample


def safe_read_text(path: Path, max_bytes: int) -> str | None:
    """
    Reads a file as text with a conservative approach.
    Returns None if file looks binary or cannot be decoded.
    """
    try:
        with path.open("rb") as f:
            chunk = f.read(min(4096, max_bytes))
            if not chunk:
                return ""
            if is_probably_binary(chunk):
                return None
            rest = f.read(max_bytes - len(chunk))
            data = chunk + rest
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def path_matches_any_glob(rel_path: str, globs: list[str]) -> bool:
    # Use fnmatch for ** patterns in a platform-neutral way (normalize to forward slashes)
    norm = rel_path.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, g.replace("\\", "/")) for g in globs)


def compute_line_col(text: str, match_start: int) -> tuple[int, int]:
    # line is 1-based, column is 1-based
    line = text.count("\n", 0, match_start) + 1
    last_nl = text.rfind("\n", 0, match_start)
    col = match_start + 1 if last_nl == -1 else match_start - last_nl
    return line, col


def normalize_snippet(snippet: str, max_len: int = 160) -> str:
    s = snippet.replace("\r", "").replace("\n", "\\n")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def fingerprint_for(rule_id: str, rel_path: str, line: int, snippet: str) -> str:
    raw = f"{rule_id}|{rel_path}|{line}|{snippet}".encode("utf-8", errors="ignore")
    h = hashlib.sha256(raw).hexdigest()
    return f"sha256:{h}"


def scan_path(
    root_path: str | Path,
    rules: list[dict[str, Any]],
    *,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    max_file_size_mb: int = 2,
) -> list[Finding]:
    """
    Walks files under root_path and applies regex rules.
    v1 is intentionally simple: content regex scanning only.
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Scan path not found: {root}")

    max_bytes = int(max_file_size_mb * 1024 * 1024)
    findings: list[Finding] = []

    # Precompile regex patterns for speed
    compiled_rules: list[dict[str, Any]] = []
    for r in rules:
        pats = []
        for p in r["patterns"]:
            try:
                pats.append(re.compile(p, flags=re.IGNORECASE))
            except re.error as ex:
                raise ValueError(f"Invalid regex in rule {r['id']}: {p} ({ex})")
        compiled_rules.append({**r, "_compiled": pats})

    for dirpath, dirnames, filenames in os.walk(root):
        # mutate dirnames in-place to skip excluded dirs
        dirnames[:] = [d for d in dirnames if not is_excluded_dir(d, exclude_globs)]

        for name in filenames:
            abs_file = Path(dirpath) / name

            try:
                rel = abs_file.relative_to(root).as_posix()
            except ValueError:
                # should not happen, but safe
                rel = abs_file.name

            # If include_globs provided, only scan matches
            if include_globs and not path_matches_any_glob(rel, include_globs):
                continue

            # Skip by exclude globs (file-level)
            if exclude_globs and any(fnmatch.fnmatch(rel, pat.replace("\\", "/")) for pat in exclude_globs):
                continue

            # Skip huge files
            try:
                if abs_file.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue

            text = safe_read_text(abs_file, max_bytes=max_bytes)
            if text is None:
                continue

            # Apply rules that match file globs
            for r in compiled_rules:
                if not path_matches_any_glob(rel, r["file_globs"]):
                    continue

                for rx in r["_compiled"]:
                    for m in rx.finditer(text):
                        line, col = compute_line_col(text, m.start())
                        snippet = normalize_snippet(text[m.start() : min(len(text), m.end() + 80)])
                        fp = fingerprint_for(r["id"], rel, line, snippet)

                        findings.append(
                            Finding(
                                rule_id=r["id"],
                                title=r["title"],
                                severity=r["severity"],
                                path=rel,
                                line=line,
                                column=col,
                                snippet=snippet,
                                fingerprint=fp,
                                description=r.get("description"),
                                confidence=r.get("confidence"),
                                category=r.get("category"),
                            )
                        )

    # Sort findings by severity desc then path/line
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.path, f.line, f.column))
    return findings


def build_summary(findings: list[Finding]) -> dict[str, Any]:
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in by_sev:
            by_sev[f.severity] += 1
    return {"total_findings": len(findings), "by_severity": by_sev}


def build_json_report(
    findings: list[Finding],
    *,
    tool_version: str,
    root: str,
    fail_on: str,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    return {
        "tool": {"name": "sap-sentinel", "version": tool_version},
        "scan": {
            "root": root,
            "started_at": started_at,
            "finished_at": finished_at,
        },
        "policy": {"fail_on": fail_on},
        "summary": build_summary(findings),
        "findings": [asdict(f) for f in findings],
    }
