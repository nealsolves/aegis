import sys
from pathlib import Path

import pytest

# Ensure demo-app-api/ is on sys.path so tests can import main, scenarios, gates
sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(autouse=True)
def _isolate_demo_rate_state():
    """Keep process-local production rate state from coupling separate tests."""

    main_module = sys.modules.get("main")
    app = getattr(main_module, "app", None)
    if app is None or not hasattr(app, "_limiter"):
        yield
        return

    from demo_edge import TokenBucketLimiter

    original = app._limiter
    app._limiter = TokenBucketLimiter()
    try:
        yield
    finally:
        app._limiter = original
