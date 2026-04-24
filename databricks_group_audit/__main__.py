"""Allow running as `python -m databricks_group_audit`."""

import sys

from databricks_group_audit.cli import main

sys.exit(main())
