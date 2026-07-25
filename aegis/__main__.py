"""Allow ``python -m aegis`` to run the CLI."""

import sys
from aegis._internal.cli import main

sys.exit(main())
