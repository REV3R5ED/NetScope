import csv
import io

import pytest

from netscope.cli import build_parser
from netscope.diagnostics import DNSResult, TCPSummaryResult
from netscope.reporting import to_csv


def _read(report: str) -> dict[str, str]:
    return next(csv.DictReader(io.StringIO(report)))


def test_csv_report_preserves_normalized_dns_result():
    report = to_csv(DNSResult("example.test", ("192.0.2.1", "2001:db8::1"), True))
    row = _read(report)

    assert list(row) == ["hostname", "addresses", "ok", "error"]
    assert row["hostname"] == "example.test"
    assert row["addresses"] == '["192.0.2.1","2001:db8::1"]'
    assert row["ok"] == "True"
    assert row["error"] == ""


def test_csv_report_preserves_summary_errors_and_latency():
    result = TCPSummaryResult(
        host="example.test",
        port=443,
        attempts=3,
        successes=2,
        failures=1,
        success_rate_percent=66.67,
        min_latency_ms=10.0,
        avg_latency_ms=15.0,
        max_latency_ms=20.0,
        jitter_ms=5.0,
        ok=True,
        errors=("connection refused, retry later",),
    )

    row = _read(to_csv(result))

    assert row["success_rate_percent"] == "66.67"
    assert row["avg_latency_ms"] == "15.0"
    assert row["jitter_ms"] == "5.0"
    assert row["errors"] == '["connection refused, retry later"]'


def test_cli_rejects_multiple_structured_output_formats():
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["dns", "example.test", "--json", "--csv"])

    assert exc.value.code == 2
