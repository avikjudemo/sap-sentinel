from __future__ import annotations

from typing import Any, Dict, List

from sap_sentinel.scripts import utc_now_iso
from sap_sentinel.btp.btp_auth import (
    load_service_key,
    get_oauth_client_credentials,
    fetch_access_token_cc,
)
from sap_sentinel.btp.client import BtpHttpClient
from sap_sentinel.btp_snapshot.schema import sanitize_destination_record


def _destination_base_url(service_key: Dict[str, Any]) -> str:
    """
    Destination service keys typically contain:
      - "uri" (Destination service API base)
    Some variants may place it in credentials.
    """
    if isinstance(service_key.get("uri"), str):
        return service_key["uri"]
    creds = service_key.get("credentials")
    if isinstance(creds, dict) and isinstance(creds.get("uri"), str):
        return creds["uri"]
    raise ValueError("Destination service key missing 'uri' (or 'credentials.uri').")


def collect_destinations_snapshot(service_key_path: str) -> Dict[str, Any]:
    """
    Uses Destination service API to collect:
      - subaccount destinations
      - instance destinations (if permitted)
    Produces a stable snapshot dict.
    """
    sk = load_service_key(service_key_path)
    creds = get_oauth_client_credentials(sk)
    token, expires_in = fetch_access_token_cc(creds)

    base = _destination_base_url(sk)
    client = BtpHttpClient(base_url=base, access_token=token)

    # Destination service API paths (documented by SAP Destination service)
    # Subaccount destinations:
    subacct = client.get_json("/destination-configuration/v1/subaccountDestinations") or []
    # Instance destinations (may fail depending on permissions/plan); handle safely:
    try:
        inst = client.get_json("/destination-configuration/v1/instanceDestinations") or []
    except Exception:
        inst = []

    subacct_s = [sanitize_destination_record(d) for d in (subacct or [])]
    inst_s = [sanitize_destination_record(d) for d in (inst or [])]

    snapshot: Dict[str, Any] = {
        "snapshot_version": "0.4.0",
        "created_at": utc_now_iso(),
        "source": {
            "collector": "destination_service",
            "base_url": base,
            "token_expires_in_s": expires_in,
        },
        "destinations": {
            "subaccount": subacct_s,
            "instance": inst_s,
            "counts": {
                "subaccount": len(subacct_s),
                "instance": len(inst_s),
            },
        },
    }
    return snapshot
