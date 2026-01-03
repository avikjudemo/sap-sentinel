from pathlib import Path
import json

class RulesetError(Exception):
    pass


# def load_rules(rules_dir: str | Path) -> list[dict]:
def load_rules(rules_dir: str | Path, *, cli_version: str | None = None) -> list[dict]:
    rules_dir = Path(rules_dir)

    # → (ADD guards + dir validation right after Path()
    if rules_dir.suffix.lower() == ".json":
        raise RulesetError(f"--rules-dir must be a directory, not a file: {rules_dir}")

    if not rules_dir.exists():
        raise RulesetError(f"Rules directory not found: {rules_dir}")

    if not rules_dir.is_dir():
        raise RulesetError(f"--rules-dir must be a directory: {rules_dir}")
    # → END

    rules_file = rules_dir / "ruleset.json"
    meta_file = rules_dir / "metadata.json"

    if not rules_file.exists():
        raise RulesetError(f"ruleset.json not found in {rules_dir}")

    if not meta_file.exists():
        raise RulesetError(f"metadata.json not found in {rules_dir}")
    
    # → START (REPLACE json.load(open()) with safe read + parse + better errors)
    try:
        metadata = json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception as ex:
        raise RulesetError(f"Invalid metadata.json (not valid JSON): {ex}")

    try:
        ruleset = json.loads(rules_file.read_text(encoding="utf-8"))
    except Exception as ex:
        raise RulesetError(f"Invalid ruleset.json (not valid JSON): {ex}")
    # → END

    # → START (ADD stronger schema validation)
    if not isinstance(ruleset, dict) or "rules" not in ruleset:
        raise RulesetError("Invalid ruleset format: missing 'rules' key")

    if not isinstance(ruleset["rules"], list):
        raise RulesetError("Invalid ruleset format: 'rules' must be a list")
    # → END

       # → START (OPTIONAL: enforce ruleset min_cli_version)
    if cli_version:
        min_cli = metadata.get("min_cli_version")
        if min_cli and _version_lt(cli_version, str(min_cli)):
            raise RulesetError(
                f"Ruleset requires CLI >= {min_cli}, but current CLI is {cli_version}"
            )
    # → END
    
        # Normalize rules (backward-compatible defaults)
    normalized: list[dict] = []
    for r in ruleset["rules"]:
        if not isinstance(r, dict):
            raise RulesetError("Invalid rule: each rule must be a JSON object")

        if "patterns" not in r or not isinstance(r["patterns"], list):
            raise RulesetError(f"Invalid rule {r.get('id', '<no id>')}: missing/invalid 'patterns' list")

        # Default: apply rule to all files if file_globs not provided
        if "file_globs" not in r:
            r["file_globs"] = ["**/*"]

        normalized.append(r)
   
    return normalized


# → START (ADD helper at bottom)
def _version_lt(a: str, b: str) -> bool:
    def parse(v: str) -> tuple[int, int, int]:
        parts = (v or "").strip().split(".")
        if len(parts) != 3:
            return (0, 0, 0)
        return (int(parts[0]), int(parts[1]), int(parts[2]))

    return parse(a) < parse(b)
# → END