"""PR-11 packaging smoke tests that avoid network dependencies by default."""
from __future__ import annotations

import importlib.util
import os
import site
import subprocess
import sys
import venv
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DISTRIBUTION = "aegis-ai-governance"
EXPECTED_VERSION = "0.9.0b1"


def _build_available() -> bool:
    try:
        return importlib.util.find_spec("build.__main__") is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _venv_python(venv_dir: Path) -> str:
    return str(venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python"))


def test_pyproject_runtime_package_boundary_is_narrow():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'name = "{EXPECTED_DISTRIBUTION}"' in text
    assert f'version = "{EXPECTED_VERSION}"' in text
    assert 'include = ["aegis", "aegis.*"]' in text
    assert "[project.optional-dependencies]" in text
    assert "openai-agents = [" in text
    project_deps = text.split("[project.optional-dependencies]", 1)[0]
    assert "openai-agents" not in project_deps


@pytest.mark.skipif(not _build_available(), reason="build module is not installed")
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
    assert [wheel.name for wheel in wheels] == [
        "aegis_ai_governance-0.9.0b1-py3-none-any.whl"
    ]
    assert [sdist.name for sdist in sdists] == [
        "aegis_ai_governance-0.9.0b1.tar.gz"
    ]

    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser(policy=default).parsebytes(
            archive.read(metadata_name)
        )
        assert metadata["Name"] == EXPECTED_DISTRIBUTION
        assert metadata["Version"] == EXPECTED_VERSION
        assert set(metadata.get_all("Requires-Dist", [])) >= {
            "PyYAML>=6.0",
            "jsonschema>=4.0",
        }
        assert "aegis/__init__.py" in archive.namelist()

    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True, system_site_packages=False)
    python = _venv_python(venv_dir)
    install = subprocess.run(
        [python, "-m", "pip", "install", "--no-deps", str(wheels[0])],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    env = os.environ.copy()
    dependency_site_packages = site.getsitepackages()[0]
    assert not (Path(dependency_site_packages) / "aegis").exists()
    env["PYTHONPATH"] = dependency_site_packages
    probe = subprocess.run(
        [
            python,
            "-c",
            "from importlib.metadata import version; "
            "import aegis; from aegis import AEGIS; "
            "from aegis.openai_agents_adapter import OpenAIAgentsAdapter; "
            "from aegis.a2a_adapter import A2AAdapter; "
            "from aegis.bedrock_adapter import BedrockTraceAdapter; "
            f"print('VERSIONS', version('{EXPECTED_DISTRIBUTION}'), "
            "aegis.__version__); "
            "print('PACKAGE_FILE', aegis.__file__); "
            "print(AEGIS, OpenAIAgentsAdapter, A2AAdapter, BedrockTraceAdapter)",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert f"VERSIONS {EXPECTED_VERSION} {EXPECTED_VERSION}" in probe.stdout
    package_line = next(
        line for line in probe.stdout.splitlines() if line.startswith("PACKAGE_FILE ")
    )
    assert Path(package_line.split(maxsplit=1)[1]).is_relative_to(venv_dir)

    cli = subprocess.run(
        [str(Path(python).parent / "aegis"), "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert cli.returncode == 0, cli.stdout + cli.stderr
    assert "workflow" in cli.stdout
