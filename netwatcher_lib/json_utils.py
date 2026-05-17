import json
from typing import Any


class DuplicateKeyError(ValueError):
    """Raised when duplicate JSON object keys are detected."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise DuplicateKeyError(f"chave JSON duplicada detectada: {key!r}")
        parsed[key] = value
    return parsed


def load_json_strict(fp: Any) -> Any:
    """json.load() com rejeição explícita de chaves duplicadas."""
    return json.load(fp, object_pairs_hook=_reject_duplicate_keys)


def loads_json_strict(payload: str) -> Any:
    """json.loads() com rejeição explícita de chaves duplicadas."""
    return json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
