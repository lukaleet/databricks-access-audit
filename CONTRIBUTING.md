# Contributing

Contributions are welcome — bug reports, documentation improvements, and pull requests all help.

## Development setup

```bash
git clone https://github.com/lukaleet/databricks-group-audit.git
cd databricks-group-audit
pip install -e ".[sdk,dev]"
```

No Databricks account is needed for development. All tests run against mocked HTTP responses.

## Running tests

```bash
# Full suite
pytest

# Single file
pytest tests/test_catalog_scanner.py

# Single test
pytest tests/test_redundancy.py::test_full_redundancy

# With coverage
pytest --cov=databricks_group_audit --cov-report=term-missing
```

## Linting

```bash
ruff check .
ruff check . --fix   # auto-fix safe issues
```

The CI gate runs both `ruff check .` and `pytest` on Python 3.9-3.12. A PR must pass both before it can be merged.

## Branch conventions

| Branch | Purpose |
|--------|---------|
| `main` | Latest stable release |
| `develop` | Integration branch - PRs target this |
| `feature/<name>` | Individual feature work |
| `fix/<name>` | Bug fixes |

Open PRs against `develop`, not `main`.

## Adding a new feature

1. Write the module in `databricks_group_audit/`.
2. Add tests in `tests/test_<module>.py` using the `responses` mock library - no real API calls.
3. Export public symbols from `databricks_group_audit/__init__.py`.
4. Wire CLI flags in `cli.py` if user-facing.
5. Update `CHANGELOG.md` under a new version heading.
6. Update `README.md` if the feature needs user documentation.

## Code style notes

- No comments unless the *why* is non-obvious (hidden constraint, workaround, subtle invariant).
- No docstrings on internal helpers - reserve them for public API classes/functions.
- `ruff` enforces line length (100) and import order - run it before pushing.
- Tests: prefer specific assertions over broad ones; each test should have a single clear failure mode.

## Reporting bugs

Open an issue at https://github.com/lukaleet/databricks-group-audit/issues with:
- Python version and OS
- CLI command or code snippet that reproduces the problem
- Full error traceback
- Databricks cloud provider (Azure / AWS / GCP) if relevant
