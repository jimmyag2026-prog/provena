"""RFC 8785 (JCS) canonical JSON, restricted to the I-JSON subset Provena signs.

Floats are rejected outright: every number in a signed structure is an integer within the
I-JSON safe range, so canonical bytes are identical in every language without float formatting.
"""

import json

from provena.core.errors import CanonicalizationError

MAX_SAFE_INT = 2**53 - 1


def _check_text(text: str, path: str) -> None:
    """Strings must be valid Unicode: lone surrogates have no UTF-8 encoding, and JavaScript
    would escape them instead of failing, splitting the verifiers."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{path}: string is not valid Unicode") from exc


def _check(value, path="$"):
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _check_text(value, path)
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalizationError(f"{path}: integer outside I-JSON range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floats are not allowed in signed structures")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check_text(key, path)
            _check(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def _serialize(value) -> str:
    if isinstance(value, dict):
        # JCS orders members by the UTF-16 code units of their names.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_serialize(k) + ":" + _serialize(v) for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def canonicalize(value) -> bytes:
    """Return the canonical UTF-8 bytes of a JSON-compatible value."""
    _check(value)
    return _serialize(value).encode("utf-8")
