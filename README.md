# SAP Sentinel

**SAP Sentinel** is a lightweight, Python-based **CI security scanner** for SAP and SAP BTP repositories.  
It runs entirely in your CI pipeline (no server required) and detects **high-risk SAP configuration and code patterns** such as hardcoded credentials, insecure destinations, and over-privileged OAuth scopes.  
The tool exits with a deterministic **0/1 status** to block merges or deployments and can emit **human-readable output, JSON, or SARIF** for dashboards and GitHub Code Scanning.

---

## Features (v1)

- Runs locally or in CI (GitHub Actions, GitLab CI, Jenkins)
- No backend, no agents, no SAP system access required
- Python-only, minimal dependencies
- Deterministic exit codes for CI gating
- SARIF output for GitHub Code Scanning
- Rules defined as data (JSON), not hardcoded logic

---

## Installation

### From GitHub (recommended for internal teams) 
# @v0.2.0 → stable
```bash
pip install git+https://github.com/avikjudemo/sap-sentinel.git@v0.3.0

