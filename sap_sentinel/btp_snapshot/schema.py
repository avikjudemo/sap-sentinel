from __future__ import annotations

from typing import Any, Dict


_SECRET_KEYS = {
    "Password",
    "password",
    "ClientSecret",
    "clientSecret",
    "clientsecret",
    "token",
    "Token",
    "refresh_token",
    "RefreshToken",
    "apikey",
    "apiKey",
    "ApiKey",
    "privateKey",
    "PrivateKey",
    "certificate",
    "Certificate",
}


def _redact_if_secret_key(key: str, value: Any) -> Any:
    if key in _SECRET_KEYS:
        return "***REDACTED***"
    return value


def sanitize_destination_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Destination records often include Authentication data and/or sensitive properties.
    We redact secrets deterministically.
    """
    out: Dict[str, Any] = {}

    for k, v in rec.items():
        if isinstance(v, dict):
            # recurse one level (good enough for destination payloads)
            out[k] = {kk: _redact_if_secret_key(kk, vv) for kk, vv in v.items()}
        else:
            out[k] = _redact_if_secret_key(k, v)

    # Some destination payloads include "destinationConfiguration" + "authTokens"
    # Ensure authTokens is always redacted if present.
    if "authTokens" in out:
        out["authTokens"] = "***REDACTED***"

    return out