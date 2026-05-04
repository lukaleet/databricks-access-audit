"""Allow running as `python -m databricks_access_audit`."""

import sys

from databricks_access_audit.cli import main

sys.exit(main())
