"""PR-11 packaging smoke tests that avoid network dependencies by default."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _venv_python(venv_dir: Path) -> str:
    return str(venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python"))


def test_pyproject_runtime_package_boundary_is_narrow():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["aegis", "aegis.*"]' in text
    assert "[project.optional-dependencies]" in text
    assert "openai-agents = [" in text
    project_deps = text.split("[project.optional-dependencies]", 1)[0]
    assert "openai-agents" not in project_deps


@pytest.mark.skipif(importlib.util.find_spec("build.__main__") is None, reason="build module is not installed")
def test_wheel_build_and_fresh_venv_import_smoke(tmp_path):
    out_dir = tmp_path / "dist"
    build = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", str(out_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = sorted(out_dir.glob("*.whl"))
    sdists = sorted(out_dir.glob("*.tar.gz"))
    assert wheels
    assert sdists

    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True, system_site_packages=True)
    python = _venv_python(venv_dir)
    install = subprocess.run(
        [python, "-m", "pip", "install", "--no-deps", str(wheels[0])],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    probe = subprocess.run(
        [
            python,
            "-c",
            "import aegis; from aegis import AEGIS; "
            "from aegis.openai_agents_adapter import OpenAIAgentsAdapter; "
            "from aegis.a2a_adapter import A2AAdapter; "
            "from aegis.bedrock_adapter import BedrockTraceAdapter; "
            "print(aegis.__version__, AEGIS, OpenAIAgentsAdapter, A2AAdapter, BedrockTraceAdapter)",
        ],
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "0.3.3" in probe.stdout
