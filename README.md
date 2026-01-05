SAP Sentinel

SAP Sentinel is a lightweight, Python-based security posture scanner for SAP and SAP BTP environments.
It is designed for local use and CI/CD pipelines, with a strict focus on determinism, transparency, and policy-as-code.

SAP Sentinel deliberately avoids SaaS backends, agents, or silent updates.
All detection logic is explicit, versioned, and reviewable.

What SAP Sentinel Does

SAP Sentinel operates in two complementary modes.

1) Repository Scanning (v0.1–v0.3)

Scan source code and configuration repositories for high-risk SAP and SAP BTP patterns, including:

Hardcoded credentials

Insecure destination definitions

Weak authentication patterns

Overly permissive configuration artifacts

This mode:

Requires no SAP system access

Works fully offline

Is ideal for CI/CD gating

2) SAP BTP Posture Scanning via Snapshots (v0.4.0)

Collect read-only SAP BTP posture data using customer-owned credentials, generate a sanitized snapshot, and evaluate it offline using versioned rules.

This enables detection of:

SAP BTP Destination misconfigurations

Cloud Connector exposure (via destination configuration)

Weak authentication patterns

TLS trust misconfigurations

Connectivity blast-radius indicators

No agents. No persistent access. No backend.

Architecture Principles

Engine ≠ Policy

CLI engine is stateless and deterministic

Detection rules live in a separate Git repository

No SaaS dependency

No silent updates

Air-gap friendly

Audit-friendly

Inputs, rules, and outputs are all versioned artifacts

Features (v0.4.0)

Runs locally or in CI (GitHub Actions, GitLab CI, Jenkins)

Deterministic exit codes for CI gating

External, versioned rulesets (policy-as-code)

Text, JSON, or SARIF output

Authenticated SAP BTP posture collection (Destinations)

Sanitized snapshot output (no secrets)

Cloud Connector risk detection via destination analysis

Installation
From GitHub
pip install git+https://github.com/avikjudemo/sap-sentinel.git@v0.4.0

Rulesets (Required)

SAP Sentinel does not bundle detection rules.

You must supply an external rules repository:

Rules repository (security / GRC teams):
https://github.com/avikjudemo/sap-sentinel-rules

Rules are explicitly pinned by path or Git reference.

Usage
Repository Scanning (v0.1–v0.3)
Basic repository scan

From the repository root you want to scan:

sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules"

Scan with explicit output format
sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules" `
  --format text


Supported formats:

text (default)

json

sarif (GitHub Code Scanning)

Write scan output to a file
sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules" `
  --format json `
  --output ".\OUTPUT\sap_sentinel_findings.json"

Fail CI on severity threshold
sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules" `
  --fail-on high


Severity levels:

off

low

medium

high

critical

Limit scan scope (recommended for large repos)

Include only specific files:

sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules" `
  --include "**/*.json" `
  --include "**/*.yaml"


Exclude folders:

sap-sentinel scan . `
  --rules-dir ".\sap-sentinel-rules" `
  --exclude ".git" `
  --exclude "node_modules" `
  --exclude "dist"

Exit codes (CI-relevant)

0 → no blocking findings

1 → severity threshold exceeded

2 → execution or configuration error

SAP BTP Posture Collection (v0.4.0)
Prerequisites

SAP BTP Destination service instance

A service key created by the customer

Read-only intent (SAP Sentinel never modifies resources)

Recommended local layout (do not commit secrets)
sap-sentinel-repo/
  secrets/
    destination-service-key.json


Add to .gitignore:

secrets/
*.service-key.json

Collect a BTP snapshot

Run from the repo root:

sap-sentinel collect btp `
  --service-key ".\secrets\destination-service-key.json"


Output:

btp_output/btp_snapshot_<timestamp>.json


The snapshot:

Contains destination configuration only

Redacts all secrets

Can be reviewed or shared explicitly

Scan a BTP snapshot
sap-sentinel scan btp_output/btp_snapshot_20260105T123000Z.json `
  --rules-dir ".\sap-sentinel-rules" `
  --format json


This enables offline SAP BTP posture analysis without live system access.

Current SAP BTP Coverage (v0.4.0)

SAP BTP Destinations

Cloud Connector exposure (via destination configuration)

Weak authentication patterns

TLS trust misconfigurations

Trial vs non-trial endpoint detection

Deep Cloud Connector configuration and XSUAA role analysis will be added in future versions when additional APIs are collected.

Known Limitations

SAP BTP trial accounts may fail authentication due to service constraints

v0.4.0 focuses on Destination service posture

XSUAA bindings and role collections are not yet collected

These are explicit design boundaries.

Why SAP Sentinel

Security teams control policy evolution

Developers get a predictable CLI

Auditors get versioned, reviewable logic

No hidden behavior

No platform lock-in

License

Apache License 2.0