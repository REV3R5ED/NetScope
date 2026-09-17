import pytest

from netscope import __version__
from netscope.cli import build_parser


def test_runtime_version_matches_release_candidate():
    assert __version__ == "0.3.0"


def test_cli_version_reports_release_candidate(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "NetScope 0.3.0"
