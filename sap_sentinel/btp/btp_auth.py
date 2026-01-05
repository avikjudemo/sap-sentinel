from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

import requests


@dataclass(frozen=True)
class OAuthClientCredentials:
    token_url: str
    client_id: str
    client_secret: str


def load_service_key(path: str | Path) -> Dict[str, Any]:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Service key JSON not found: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as ex:
        raise ValueError(f"Invalid JSON in service key file: {p} ({ex})") from ex


def _extract_uaa_block(service_key: Dict[str, Any]) -> Dict[str, Any]:
    # Common patterns:
    # - service_key["uaa"] exists (many service keys)
    # - service_key["credentials"]["uaa"] (some CF-style exports)
    if "uaa" in service_key and isinstance(service_key["uaa"], dict):
        return service_key["uaa"]
    creds = service_key.get("credentials")
    if isinstance(creds, dict) and isinstance(creds.get("uaa"), dict):
        return creds["uaa"]
    raise ValueError(
        "Cannot find UAA credentials in service key. Expected 'uaa' or 'credentials.uaa'."
    )


def get_oauth_client_credentials(service_key: Dict[str, Any]) -> OAuthClientCredentials:
    uaa = _extract_uaa_block(service_key)

    url = uaa.get("url")
    client_id = uaa.get("clientid") or uaa.get("client_id")
    client_secret = uaa.get("clientsecret") or uaa.get("client_secret")

    if not url or not client_id or not client_secret:
        raise ValueError(
            "Service key UAA block missing one of: url, clientid, clientsecret."
        )

    # Standard XSUAA token endpoint
    token_url = url.rstrip("/") + "/oauth/token"
    return OAuthClientCredentials(
        token_url=token_url,
        client_id=str(client_id),
        client_secret=str(client_secret),
    )


def fetch_access_token_cc(creds: OAuthClientCredentials, timeout_s: int = 30) -> Tuple[str, int]:
    """
    Client Credentials token fetch.
    Returns (access_token, expires_in_seconds).
    """
    basic = f"{creds.client_id}:{creds.client_secret}".encode("utf-8")
    auth_header = base64.b64encode(basic).decode("utf-8")

    resp = requests.post(
        creds.token_url,
        headers={
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "client_credentials"},
        timeout=timeout_s,
    )

    if resp.status_code >= 400:
        raise RuntimeError(
            f"OAuth token fetch failed ({resp.status_code}): {resp.text}"
        )

    data = resp.json()
    token = data.get("access_token")
    expires_in = int(data.get("expires_in") or 0)

    if not token:
        raise RuntimeError("OAuth token response missing 'access_token'.")
    return str(token), expires_in
