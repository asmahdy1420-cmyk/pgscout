"""A small JSON Schema subset validator for tool arguments.

Supports the keywords the tool schemas use: ``type``, ``properties``,
``required``, ``additionalProperties`` (boolean), ``enum``, ``minimum``,
``maximum``, ``minLength``, ``maxLength``, ``items`` and ``default``.
"""

from __future__ import annotations

from typing import Any


class ValidationError(ValueError):
    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path


_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "null": type(None),
}


def _is_type(value: Any, expected: str) -> bool:
    if expected in {"integer", "number"} and isinstance(value, bool):
        return False  # bool is a subclass of int in Python, not in JSON
    return isinstance(value, _TYPES[expected])


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> dict[str, Any]:
    """Validate ``instance`` and return it with defaults applied (objects only)."""
    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(instance, t) for t in options):
            raise ValidationError(path, f"expected {' or '.join(options)}, got {_json_type(instance)}")

    if "enum" in schema and instance not in schema["enum"]:
        raise ValidationError(path, f"must be one of {schema['enum']}")

    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            raise ValidationError(path, f"must be at least {schema['minLength']} characters")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise ValidationError(path, f"must be at most {schema['maxLength']} characters")

    if _is_type(instance, "number"):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ValidationError(path, f"must be >= {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            raise ValidationError(path, f"must be <= {schema['maximum']}")

    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            validate(item, schema["items"], f"{path}[{i}]")

    if isinstance(instance, dict):
        properties: dict[str, Any] = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in instance:
                raise ValidationError(f"{path}.{name}", "is required")
        if schema.get("additionalProperties", True) is False:
            extra = sorted(set(instance) - set(properties))
            if extra:
                raise ValidationError(path, f"unexpected argument(s): {', '.join(extra)}")
        result = dict(instance)
        for name, sub in properties.items():
            if name in result:
                validate(result[name], sub, f"{path}.{name}")
            elif "default" in sub:
                result[name] = sub["default"]
        return result
    return instance


def _json_type(value: Any) -> str:
    for name in _TYPES:
        if name != "number" and _is_type(value, name):
            return name
    return "number" if _is_type(value, "number") else type(value).__name__
