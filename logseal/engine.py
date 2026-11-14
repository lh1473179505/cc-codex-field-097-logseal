from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any

_TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def _signing_input(entry: dict[str, Any]) -> bytes:
    for field in ("seq", "ts", "actor", "action", "body_sha256", "prev_hash"):
        if field not in entry:
            raise ValueError(f"entry missing required field: {field}")
    seq = entry["seq"]
    ts = entry["ts"]
    actor = entry["actor"]
    action = entry["action"]
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise ValueError("seq must be an integer")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise ValueError("ts must be an integer")
    if not isinstance(actor, str) or not _TOKEN_RE.match(actor):
        raise ValueError("actor must be an ASCII token")
    if not isinstance(action, str) or not _TOKEN_RE.match(action):
        raise ValueError("action must be an ASCII token")
    line = "{}|{}|{}|{}|{}|{}|{}".format(
        "v1",
        seq,
        ts,
        actor,
        action,
        entry["body_sha256"],
        entry["prev_hash"],
    )
    return line.encode("ascii")


def _key_material(secret: Any) -> bytes:
    if not isinstance(secret, str):
        raise ValueError("key secret must be a string")
    if len(secret) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]*", secret):
        return bytes.fromhex(secret)
    return secret.encode("utf-8")


def _seal(entry: dict[str, Any], secret: Any) -> str:
    digest = hmac.new(
        _key_material(secret), _signing_input(entry), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


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
    """Verify a sealed log and return a report per docs/report-schema.md."""
    key_map = keys["keys"]
    genesis_hash = policy["genesis_hash"]
    start_seq = policy["start_seq"]
    skew = policy["clock_skew_seconds"]
    require_terminal = policy.get("require_terminal_seal", False)

    reasons: set[str] = set()
    kids: list[str] = []
    seen_seqs: set[int] = set()
    prev_seq: int | None = None
    prev_ts: int | None = None
    prev_input: bytes | None = None

    for entry in entries:
        signing_input = _signing_input(entry)
        seq = entry["seq"]
        ts = entry["ts"]
        kid = entry.get("kid")

        if entry.get("version") != "v1":
            reasons.add("version_rejected")

        if kid not in kids:
            kids.append(kid)
        key = key_map[kid]  # unknown kid -> KeyError (CLI exit 2)
        if key.get("status") == "revoked":
            reasons.add("kid_revoked")
        if not (key["not_before"] <= ts <= key["not_after"]):
            reasons.add("kid_outside_epoch")

        if not hmac.compare_digest(_seal(entry, key["secret"]), entry.get("seal", "")):
            reasons.add("bad_signature")

        if prev_input is None:
            if entry["prev_hash"] != genesis_hash:
                reasons.add("broken_chain")
        else:
            expected = hashlib.sha256(prev_input).hexdigest()
            if entry["prev_hash"] != expected:
                reasons.add("broken_chain")

        if seq in seen_seqs:
            reasons.add("dup_seq")
        elif prev_seq is None:
            if seq != start_seq:
                reasons.add("gap")
        elif seq != prev_seq + 1:
            reasons.add("gap")
        seen_seqs.add(seq)
        prev_seq = seq

        if abs(now_unix - ts) > skew:
            reasons.add("timestamp_skew")
        if prev_ts is not None and ts < prev_ts:
            reasons.add("timestamp_order")
        prev_ts = ts

        if "body" in entry:
            body = entry["body"]
            if not isinstance(body, (bytes, bytearray)):
                raise ValueError("entry body must be bytes")
            if hashlib.sha256(bytes(body)).hexdigest() != entry["body_sha256"]:
                reasons.add("body_mismatch")

        prev_input = signing_input

    if require_terminal:
        if not entries or entries[-1].get("action") != "TERMINAL":
            reasons.add("truncated")

    reason_codes = sorted(reasons)
    return {
        "decision": "allow" if not reason_codes else "deny",
        "reason_codes": reason_codes,
        "entry_count": len(entries),
        "head_seq": entries[0].get("seq") if entries else None,
        "tail_seq": entries[-1].get("seq") if entries else None,
        "tip_hash": hashlib.sha256(prev_input).hexdigest() if entries else None,
        "kids": kids,
        "notes": [],
    }
