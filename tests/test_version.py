"""Version metadata stays single-sourced from the installed package metadata."""

from __future__ import annotations

import re
from importlib.metadata import version
from pathlib import Path

import pytest

from netscope import __version__
from netscope.cli import build_parser


def test_runtime_version_matches_installed_package_metadata():
    assert __version__ == version("netscope-toolkit")


def test_runtime_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
    assert match is not None
    assert __version__ == match.group(1)


def test_cli_version_reports_runtime_version(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"NetScope {__version__}"
