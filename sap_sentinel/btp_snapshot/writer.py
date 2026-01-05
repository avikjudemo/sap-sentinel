from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def write_snapshot_json(snapshot: Dict[str, Any], output_path: str) -> str:
    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False)
    out.write_text(payload, encoding="utf-8")
    return str(out)