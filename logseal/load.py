from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def load_log(path: str | Path) -> list:
    data = load_json(path)
    if not isinstance(data, list):
        raise ValueError("log must be a JSON array")
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("log entries must be objects")
    return data
