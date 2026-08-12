"""
Lazy logging bootstrap for legacy signer operations.

Imported only from ``signing._logger()`` at call time so importing the
signing module never touches ``logging``. The import machinery's module
lock makes this body run exactly once per interpreter, which installs at
most one ``NullHandler`` without needing ``threading`` (an ambient
capability excluded from the checkpoint verification closure) or the
private ``logging._acquireLock`` API removed in Python 3.13.
"""

import logging

logger = logging.getLogger("aegis.signing")
if not any(type(handler) is logging.NullHandler for handler in logger.handlers):
    logger.addHandler(logging.NullHandler())
