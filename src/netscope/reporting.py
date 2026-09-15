"""Deterministic export helpers for NetScope diagnostic results."""

from __future__ import annotations

import csv
import io
import json
from typing import Protocol


class DictResult(Protocol):
    """Minimal protocol implemented by normalized diagnostic result models."""

    def to_dict(self) -> dict[str, object]: ...


def _csv_value(value: object) -> object:
    """Normalize compound values without losing their structure."""
    if isinstance(value, (tuple, list, dict)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    if value is None:
        return ""
    return value


def to_csv(result: DictResult) -> str:
    """Serialize one diagnostic result as a stable one-record CSV report.

    Field order follows the result dataclass definition, while compound values
    are encoded as compact JSON so addresses and error collections remain
    machine-readable instead of being flattened ambiguously.
    """
    data = result.to_dict()
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(data))
    writer.writeheader()
    writer.writerow({key: _csv_value(value) for key, value in data.items()})
    return output.getvalue()
