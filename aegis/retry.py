"""Public API wrapper for retry policy enforcement."""

from aegis._internal.retry import with_retry, RetryExhaustedError

__all__ = ["with_retry", "RetryExhaustedError"]
