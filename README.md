SAP Sentinel

SAP Sentinel is a lightweight, Python-based security posture scanner for SAP and SAP BTP environments.
It is designed for CI/CD pipelines and local security reviews, with a strict focus on determinism, transparency, and policy-as-code.

SAP Sentinel deliberately avoids SaaS backends, agents, or silent updates.
All detection logic is versioned, reviewable, and pinned by the user.

What SAP Sentinel Does

SAP Sentinel operates in two complementary modes:

1) Repository scanning (v0.1–v0.3)

Scan source code and configuration repositories for high-risk SAP and BTP patterns:

Hardcoded credentials

Insecure destination definitions

Weak authentication patterns

Overly permissive configuration artifacts

2) BTP posture scanning via snapshots (v0.4.0)

Collect read-only SAP BTP posture data using customer-owned credentials, produce a sanitized snapshot, and evaluate it offline using versioned rules.

This enables security analysis of:

SAP BTP Destinations

Cloud Connector exposure (via destination configuration)

Authentication and TLS misconfigurations

Connectivity blast radius indicators

No live system scanning. No agents. No persistent access.

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

Local or CI execution (GitHub Actions, GitLab CI, Jenkins)

Deterministic exit codes for CI gating

External, versioned rulesets (policy-as-code)

Human-readable, JSON, or SARIF output

Authenticated SAP BTP posture collection (Destinations)

Sanitized snapshot output (no secrets)

Cloud Connector risk detection (via destination analysis)

Installation
From GitHub (recommended)
pip install git+https://github.com/avikjudemo/sap-sentinel.git@v0.4.0

Rulesets (required)

SAP Sentinel does not bundle detection rules.

You must provide an external rules repository:

Rules repo (security / GRC teams):
https://github.com/avikjudemo/sap-sentinel-rules

Rules are pinned explicitly by path or Git reference.

Usage
1) Scan a repository (existing behavior)
sap-sentinel scan . \
  --rules-dir ../sap-sentinel-rules \
  --format text


Exit code:

0 → no blocking findings

1 → severity threshold exceeded

2 → execution error

2) Collect SAP BTP posture (v0.4.0)
Prerequisites

SAP BTP Destination service instance

A service key created by the customer

Read-only intent (SAP Sentinel does not modify anything)

Recommended folder layout

Service keys must not be committed.

sap-sentinel-repo/
  secrets/
    destination-service-key.json   (gitignored)


Add to .gitignore:

secrets/
*.service-key.json

Collect a BTP snapshot

From the repository root:

sap-sentinel collect btp `
  --service-key ".\secrets\destination-service-key.json"


Output:

btp_output/btp_snapshot_<timestamp>.json


The snapshot:

Contains destination configuration only

Has all secrets redacted

Is safe to store, review, or share explicitly

3) Scan a BTP snapshot (example using json snapshot collected)
sap-sentinel scan btp_output/btp_snapshot_20260105T123000Z.json \
  --rules-dir ../sap-sentinel-rules \
  --format json


This enables offline posture analysis without live BTP access.

Current BTP Coverage (v0.4.0)

SAP BTP Destinations

Cloud Connector exposure (via destination configuration)

Weak authentication patterns

TLS trust misconfigurations

Trial vs non-trial endpoint detection

Note: Deep Cloud Connector configuration and XSUAA role analysis will be added in future versions when additional APIs are collected.

Known Limitations

SAP BTP trial accounts may fail authentication due to service constraints

v0.4.0 focuses on Destination service posture

XSUAA bindings and role collections are not yet collected

These are design choices, not gaps in intent.

Why SAP Sentinel

Security teams control policy evolution

Developers get a predictable CLI

Auditors get versioned, reviewable logic

No hidden behavior

No platform lock-in

License

Apache 2.0