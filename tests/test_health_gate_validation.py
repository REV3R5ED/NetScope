"""Regression coverage for bounded TCP-summary health-gate parsing."""

from __future__ import annotations

import pytest

from netscope import cli


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "+inf", "-inf"])
def test_min_success_rate_rejects_non_finite_values(value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["tcp-summary", "example.com", "443", "--min-success-rate", value])
    assert exc.value.code == 2


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "+inf", "-inf"])
def test_max_jitter_rejects_non_finite_values(value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["tcp-summary", "example.com", "443", "--max-jitter-ms", value])
    assert exc.value.code == 2


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "+inf", "-inf", "-0.1"])
def test_max_average_latency_rejects_invalid_values(value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["tcp-summary", "example.com", "443", "--max-avg-latency-ms", value])
    assert exc.value.code == 2
