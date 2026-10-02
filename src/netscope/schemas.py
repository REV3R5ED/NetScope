"""Versioned JSON Schema documents for NetScope command output.

The schema documents live in ``netscope/schemas/<command>.schema.json`` and are
bundled with the package. ``netscope schema COMMAND`` prints a document, and
the CI contract test validates every command's ``--json`` output against its
schema with the minimal validator below.

Schema versioning: each document carries an integer ``version`` and a ``$id``
containing ``/vN/``. Additive changes (new optional properties) bump the
document version in place; breaking changes (removed or retyped properties)
are published as a new ``/vN+1/`` document while the previous version keeps
shipping.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

SCHEMA_VERSION = 1

COMMANDS = (
    "interfaces",
    "address",
    "network",
    "dns",
    "tcp",
    "tcp-summary",
    "path",
    "ping",
    "tls",
)


class SchemaError(ValueError):
    """Raised when a schema document cannot be loaded."""


def schema_names() -> tuple[str, ...]:
    """Return the commands that have a published JSON Schema document."""
    return COMMANDS


def load_schema(command: str) -> dict[str, Any]:
    """Load the parsed JSON Schema document for a command."""
    if command not in COMMANDS:
        raise SchemaError(
            f"no schema for {command!r}; available: {', '.join(COMMANDS)}"
        )
    resource = (
        resources.files("netscope")
        .joinpath("schemas")
        .joinpath(f"{command}.schema.json")
    )
    try:
        with resource.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load schema for {command!r}: {exc}") from None
    if not isinstance(document, dict):
        raise SchemaError(f"schema for {command!r} is not a JSON object")
    return document


def _type_matches(expected: str, instance: Any) -> bool:
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    if expected == "array":
        return isinstance(instance, list)
    if expected == "object":
        return isinstance(instance, dict)
    return False  # pragma: no cover - schemas only use the types above


def _validate(schema: dict[str, Any], instance: Any, path: str) -> list[str]:
    """Validate an instance against the supported schema subset.

    Supports ``type`` (single or array), ``enum``, ``minimum``, ``maximum``,
    ``required``, ``properties``, ``items``, and ``additionalProperties``.
    Returns a list of human-readable violations; empty means valid.
    """
    errors: list[str] = []
    expected = schema.get("type")
    if expected is not None:
        expected_types = [expected] if isinstance(expected, str) else expected
        if not any(
            _type_matches(name, instance)
            for name in expected_types
            if isinstance(name, str)
        ):
            errors.append(
                f"{path}: expected type {expected}, got {type(instance).__name__}"
            )
            return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")
    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                errors.append(f"{path}: missing required property {required!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                errors.extend(_validate(properties[key], value, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key!r}")
    if isinstance(instance, list) and "items" in schema:
        for index, value in enumerate(instance):
            errors.extend(_validate(schema["items"], value, f"{path}[{index}]"))
    if (
        isinstance(instance, (int, float))
        and not isinstance(instance, bool)
        and "minimum" in schema
        and instance < schema["minimum"]
    ):
        errors.append(f"{path}: {instance} is below minimum {schema['minimum']}")
    if (
        isinstance(instance, (int, float))
        and not isinstance(instance, bool)
        and "maximum" in schema
        and instance > schema["maximum"]
    ):
        errors.append(f"{path}: {instance} is above maximum {schema['maximum']}")
    return errors


def validate_against_schema(command: str, payload: Any) -> list[str]:
    """Validate a command's JSON payload; return violations (empty when valid)."""
    return _validate(load_schema(command), payload, "$")
