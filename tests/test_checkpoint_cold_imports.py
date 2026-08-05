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
