from __future__ import annotations

from typing import Any


def inspect_log(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "seq": entry.get("seq"),
            "ts": entry.get("ts"),
            "actor": entry.get("actor"),
            "prev_hash": entry.get("prev_hash"),
            "kid": entry.get("kid"),
        }
        for entry in entries
    ]


def verify_log(
    entries: list[dict[str, Any]],
    keys: dict[str, Any],
    policy: dict[str, Any],
    now_unix: int,
) -> dict[str, Any]:
    """Verify a sealed log. Stub — raise until implemented."""
    raise NotImplementedError(
        "logseal.engine.verify_log is not implemented yet; inspect works"
    )
