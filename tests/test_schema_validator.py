"""Edge-case coverage for the minimal JSON Schema validator."""

from __future__ import annotations

import pytest

from netscope import schemas
from netscope.schemas import (
    SchemaError,
    _validate,
    load_schema,
    validate_against_schema,
)


def test_load_schema_rejects_unknown_command():
    with pytest.raises(SchemaError, match="no schema"):
        load_schema("nope")


def test_load_schema_reports_unreadable_document(monkeypatch):
    class _FailingFiles:
        def joinpath(self, *args):
            return self

        def open(self, *args, **kwargs):
            raise OSError("disk gone")

    monkeypatch.setattr(schemas.resources, "files", lambda package: _FailingFiles())
    with pytest.raises(SchemaError, match="cannot load schema"):
        load_schema("tcp")


def test_load_schema_rejects_non_object_document(monkeypatch):
    import io

    class _BadFiles:
        def joinpath(self, *args):
            return self

        def open(self, *args, **kwargs):
            return io.StringIO("[1, 2]")

    monkeypatch.setattr(schemas.resources, "files", lambda package: _BadFiles())
    with pytest.raises(SchemaError, match="not a JSON object"):
        load_schema("tcp")


def test_validator_enum_minimum_maximum():
    schema = {
        "type": "object",
        "properties": {
            "level": {"type": "string", "enum": ["low", "high"]},
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
        },
        "required": ["level", "count"],
    }
    assert _validate(schema, {"level": "low", "count": 5}, "$") == []
    violations = _validate(schema, {"level": "medium", "count": 0}, "$")
    assert len(violations) == 2
    violations = _validate(schema, {"level": "high", "count": 11}, "$")
    assert any("above maximum" in violation for violation in violations)


def test_validator_boolean_not_number_or_integer():
    schema = {"type": "object", "properties": {"flag": {"type": "boolean"}}}
    assert _validate(schema, {"flag": True}, "$") == []
    assert _validate(schema, {"flag": 1}, "$") != []


def test_validator_nested_arrays_and_missing_required():
    schema = {
        "type": "object",
        "properties": {"tags": {"type": "array", "items": {"type": "string"}}},
        "required": ["tags", "name"],
    }
    assert _validate(schema, {"tags": ["a"], "name": "n"}, "$") == []
    violations = _validate(schema, {"tags": ["a", 1]}, "$")
    assert any("[1]" in violation for violation in violations)
    violations = _validate(schema, {"tags": []}, "$")
    assert any("missing required property 'name'" in v for v in violations)


def test_validate_against_schema_end_to_end_type_mismatch():
    payload = {
        "host": "example.test",
        "port": "443",
        "ok": True,
        "latency_ms": None,
        "error": None,
    }
    violations = validate_against_schema("tcp", payload)
    assert any("$.port" in violation for violation in violations)
