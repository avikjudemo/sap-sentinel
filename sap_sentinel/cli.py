from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sap_sentinel.models import should_fail
from sap_sentinel.rules.loader import load_rules
from sap_sentinel.scripts import scan_path, utc_now_iso

from sap_sentinel.output.text import emit_text
from sap_sentinel.output.json_out import emit_json
from sap_sentinel.output.sarif import emit_sarif

# added imports for BTP destination snapshot collection-v0.4.0
from sap_sentinel.btp.collect import collect_destinations_snapshot
from sap_sentinel.btp_snapshot.writer import write_snapshot_json
from sap_sentinel.btp_output.paths import default_snapshot_path



TOOL_VERSION = "0.4.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sap-sentinel",
        description="SAP Sentinel - repo scanner for SAP/BTP security misconfigurations (v0.4.0).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a path (repo folder) for findings.")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")

    scan.add_argument(
        "--rules-dir",
        required=True,
        help="Path to external rules repo directory (must contain ruleset.json + metadata.json).",
    )

    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan.add_argument(
        "--output",
        default="",
        help="Output file path. If omitted, writes to stdout.",
    )
    scan.add_argument(
        "--fail-on",
        choices=["off", "low", "medium", "high", "critical"],
        default="high",
        help="Fail (exit 1) if any finding severity is >= this level (default: high).",
    )
    scan.add_argument(
        "--include",
        action="append",
        default=[],
        help="Only scan files matching this glob (repeatable).",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude files/dirs matching this glob or dir name (repeatable).",
    )
    scan.add_argument(
        "--max-file-size-mb",
        type=int,
        default=2,
        help="Skip files larger than this size in MB (default: 2).",
    )

    collect = sub.add_parser("collect", help="Collect BTP posture data into a snapshot file.")
    collect_sub = collect.add_subparsers(dest="collect_target", required=True)

    btp = collect_sub.add_parser("btp", help="Collect Destinations posture via Destination service key.")
    btp.add_argument(
        "--service-key",
        required=True,
        help="Path to Destination service key JSON (used for OAuth client_credentials).",
    )
    btp.add_argument(
        "--output",
        default="",
        help="Output snapshot path (default: btp_output/btp_snapshot_<timestamp>.json).",
    )


    return parser


def write_output(text: str, output_path: str) -> None:
    if not output_path:
        sys.stdout.write(text)
        return

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "collect":
        if args.collect_target != "btp":
            parser.error("Unknown collect target")

        try:
            snapshot = collect_destinations_snapshot(args.service_key)
            out_path = args.output or default_snapshot_path()
            written = write_snapshot_json(snapshot, out_path)
        except Exception as ex:
            sys.stderr.write(f"SAP Sentinel error: {ex}\n")
            raise SystemExit(2)

        sys.stdout.write(f"Wrote snapshot: {written}\n")
        raise SystemExit(0)
    

    if args.command != "scan":
        parser.error("Unknown command")

    root = str(Path(args.path).resolve())
    started_at = utc_now_iso()

    rules_dir = Path(args.rules_dir).resolve()

    try:
        rules = load_rules(rules_dir)
        findings = scan_path(
            root,
            rules,
            include_globs=args.include or None,
            exclude_globs=args.exclude or None,
            max_file_size_mb=args.max_file_size_mb,
        )
    except Exception as ex:
        sys.stderr.write(f"SAP Sentinel error: {ex}\n")
        raise SystemExit(2)

    finished_at = utc_now_iso()

    fmt = args.format
    if fmt == "text":
        out_text = emit_text(findings)
    elif fmt == "json":
        out_text = emit_json(
            findings,
            tool_version=TOOL_VERSION,
            root=root,
            fail_on=args.fail_on,
            started_at=started_at,
            finished_at=finished_at,
        )
    elif fmt == "sarif":
        out_text = emit_sarif(findings, tool_version=TOOL_VERSION)
    else:
        sys.stderr.write(f"Unsupported format: {fmt}\n")
        raise SystemExit(2)

    write_output(out_text, args.output)

    fail = should_fail(findings, args.fail_on)
    raise SystemExit(1 if fail else 0)