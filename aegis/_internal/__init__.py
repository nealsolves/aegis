"""
Internal implementation details. No compatibility guarantees.

All public symbols should be imported from the top-level ``aegis`` package.
Importing from ``aegis._internal`` is deprecated and will emit a
DeprecationWarning.
"""

import warnings as _warnings

_EXPORTS = {
    "enforce_invocation": "aegis._internal.enforcement",
    "with_retry": "aegis._internal.retry",
    "RetryExhaustedError": "aegis._internal.retry",
    "AIGCError": "aegis._internal.errors",
    "FeatureNotImplementedError": "aegis._internal.errors",
    "GovernanceViolationError": "aegis._internal.errors",
    "InvocationValidationError": "aegis._internal.errors",
    "PolicyLoadError": "aegis._internal.errors",
    "PolicyValidationError": "aegis._internal.errors",
    "PreconditionError": "aegis._internal.errors",
    "SchemaValidationError": "aegis._internal.errors",
}


def __getattr__(name: str):
    if name in _EXPORTS:
        _warnings.warn(
            f"Importing '{name}' from 'aegis._internal' is deprecated. "
            f"Use 'from aegis import {name}' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        import importlib
        mod = importlib.import_module(_EXPORTS[name])
        return getattr(mod, name)
    raise AttributeError(f"module 'aegis._internal' has no attribute {name}")
