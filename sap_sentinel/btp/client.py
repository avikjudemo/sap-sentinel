from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class BtpHttpClient:
    base_url: str
    access_token: str
    timeout_s: int = 30

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = self.base_url.rstrip("/") + "/" + path.lstrip("/")
        resp = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout_s)
        if resp.status_code >= 400:
            raise RuntimeError(f"GET {url} failed ({resp.status_code}): {resp.text}")
        if not resp.text.strip():
            return None
        return resp.json()
