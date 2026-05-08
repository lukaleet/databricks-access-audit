# databricks-access-audit

> Databricks gives you no native way to answer *"what can this identity access across all my workspaces?"* — this tool does.

[![CI](https://img.shields.io/github/actions/workflow/status/lukaleet/databricks-access-audit/ci.yml?branch=main&label=CI)](https://github.com/lukaleet/databricks-access-audit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/databricks-access-audit)](https://pypi.org/project/databricks-access-audit/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

The Account Console shows you one workspace at a time. `INFORMATION_SCHEMA` shows you one metastore at a time. Neither resolves nested group memberships. Neither tells you whether a personal grant duplicates what the group already provides.

`databricks-access-audit` answers cross-workspace access questions in one command, across every workspace in your account at once.

## Five modes

| Mode | Command | Question it answers |
|---|---|---|
| **Principal audit** | `--principal "alice@company.com"` | What can this user / SP / group access across every workspace? |
| **Group audit** | `--group "data-engineers"` | What does this group access? Who has redundant personal grants? |
| **Resource audit** | `--resource "main"` | Who has access to this catalog / schema / table / workspace? |
| **Compare** | `--compare "alice@company.com" "bob@company.com"` | Which groups does Alice have that Bob doesn't? |
| **Access provisioning** | `--clone-from "alice@company.com" --to "bob@company.com"` | How do I give Bob the same access as Alice? |

## Install

```bash
pip install "databricks-access-audit[sdk]"
```

Add credentials to `~/.databrickscfg` and run:

```bash
databricks-access-audit --principal "alice@company.com"
databricks-access-audit --group "data-engineers" --revoke-script
databricks-access-audit --resource "main" --output html > main_access.html
```

## Documentation

**[https://lukaleet.github.io/databricks-access-audit](https://lukaleet.github.io/databricks-access-audit)**

- [Getting Started](https://lukaleet.github.io/databricks-access-audit/getting-started/) — install, credentials, first audit
- [Capabilities](https://lukaleet.github.io/databricks-access-audit/capabilities/) — how each feature works
- [Use Cases](https://lukaleet.github.io/databricks-access-audit/use-cases/offboarding/) — offboarding, onboarding, access review, incident response, compliance
- [CLI Reference](https://lukaleet.github.io/databricks-access-audit/reference/cli/) — every flag documented
- [Troubleshooting](https://lukaleet.github.io/databricks-access-audit/troubleshooting/) — common issues and fixes

## Tested environments

Developed and live-tested against Azure Databricks with Unity Catalog. AWS and GCP code paths exist but haven't been confirmed against real accounts yet.

If you run this on AWS, GCP, a large multi-workspace account, or with Okta/AWS SSO as your IdP — [open an issue](https://github.com/lukaleet/databricks-access-audit/issues) and let us know what works and what doesn't. Every environment report improves the tool.

## Development

```bash
pip install -e ".[sdk,dev]"
pytest          # 570 tests, no real Databricks connection required
ruff check .
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
