"""Fresh-interpreter proofs for the checkpoint import boundary."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "module_name",
    ("aegis.checkpoints", "aegis.workflow_verification"),
)
def test_checkpoint_public_module_import_does_not_reach_capability_modules(
    module_name: str,
) -> None:
    """Catch any package-facade import of an enforcement/capability module."""
    script = r'''
import importlib
import importlib.abc
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

blocked = (
    "aegis.enforcement",
    "aegis._internal.enforcement",
    "aegis._internal.evidence_finalizer",
    "aegis.retry",
    "aegis._internal.retry",
    "aegis.session",
    "aegis._internal.session",
    "aegis.sinks",
    "aegis._internal.sinks",
    "jsonschema",
)
sys.path.insert(0, sys.argv[2])

def forbidden_capability(*args, **kwargs):
    del args, kwargs
    raise RuntimeError("checkpoint import executed an ambient capability")

os.getenv = forbidden_capability
os.putenv = forbidden_capability
Path.open = forbidden_capability
Path.read_bytes = forbidden_capability
Path.read_text = forbidden_capability
Path.write_bytes = forbidden_capability
Path.write_text = forbidden_capability
socket.socket = forbidden_capability
threading.Lock = forbidden_capability
time.sleep = forbidden_capability
time.time = forbidden_capability

class BoundaryProbe(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if any(fullname == name or fullname.startswith(name + ".") for name in blocked):
            raise RuntimeError("forbidden checkpoint import: " + fullname)
        return None

sys.meta_path.insert(0, BoundaryProbe())
try:
    before = frozenset(sys.modules)
    imported = importlib.import_module(sys.argv[1])
except BaseException as error:
    print(json.dumps({"ok": False, "error": str(error)}))
else:
    loaded = sorted(
        name for name in set(sys.modules) - before
        if any(
            name == blocked_name or name.startswith(blocked_name + ".")
            for blocked_name in blocked
        )
    )
    print(json.dumps({"ok": True, "name": imported.__name__, "blocked": loaded}))
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, module_name, str(_ROOT)],
        cwd=_ROOT,
        env={"PYTHONPATH": str(_ROOT)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {"ok": True, "name": module_name, "blocked": []}


def test_lazy_top_level_exports_preserve_identity_star_import_and_reload() -> None:
    """Catch a facade that changes the documented API while becoming lazy."""
    import importlib

    import aegis

    namespace: dict[str, object] = {}
    exec("from aegis import *", namespace)

    assert frozenset(namespace) >= frozenset(aegis.__all__)
    for name in aegis.__all__:
        assert namespace[name] is getattr(aegis, name)

    checkpoint_type = aegis.TrustedChainCheckpoint
    assert checkpoint_type is importlib.import_module(
        "aegis.checkpoints"
    ).TrustedChainCheckpoint
    assert importlib.reload(aegis).TrustedChainCheckpoint is checkpoint_type


def test_top_level_checkpoint_exports_are_pinned_and_reload_overwrites_stale_values(
) -> None:
    import importlib

    import aegis
    import aegis.checkpoints as checkpoints

    canonical = checkpoints.TrustedChainCheckpoint
    sentinel = object()
    try:
        checkpoints.TrustedChainCheckpoint = sentinel  # type: ignore[misc]
        assert aegis.TrustedChainCheckpoint is canonical
    finally:
        checkpoints.TrustedChainCheckpoint = canonical

    aegis.TrustedChainCheckpoint = sentinel  # type: ignore[misc]
    assert importlib.reload(aegis).TrustedChainCheckpoint is canonical


def test_legacy_warning_lazily_installs_one_null_handler_without_last_resort_output(
) -> None:
    script = r'''
import importlib
import json
import sys

sys.path.insert(0, sys.argv[1])
import aegis._internal.signing as signing

logging_was_cold = "logging" not in sys.modules
signer = signing.HMACSigner(b"key")
signing.verify_artifact({"signature": None}, signer)

import logging
logger = logging.getLogger("aegis.signing")
records = []
class Capture(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())
capture = Capture()
logger.addHandler(capture)
signing.verify_artifact({"signature": None}, signer)
before_reload = sum(type(handler) is logging.NullHandler for handler in logger.handlers)
signing = importlib.reload(signing)
signing.verify_artifact({"signature": None}, signer)
after_reload = sum(type(handler) is logging.NullHandler for handler in logger.handlers)
print(json.dumps({
    "logging_was_cold": logging_was_cold,
    "before_reload": before_reload,
    "after_reload": after_reload,
    "capture_preserved": capture in logger.handlers,
    "record_count": len(records),
}))
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(_ROOT)],
        cwd=_ROOT,
        env={"PYTHONPATH": str(_ROOT)},
        text=True,
        capture_output=True,
        check=True,
    )

    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "logging_was_cold": True,
        "before_reload": 1,
        "after_reload": 1,
        "capture_preserved": True,
        "record_count": 2,
    }
