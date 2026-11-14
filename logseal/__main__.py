from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine import inspect_log, verify_log
from .load import load_json, load_log


def _parse_now(value: str) -> int:
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _attach_bodies(entries: list[dict], bodies: str | None) -> list[dict]:
    if not bodies:
        return entries
    root = Path(bodies)
    attached = []
    for entry in entries:
        item = dict(entry)
        seq = item.get("seq")
        path = root / f"{seq}.bin"
        if not path.is_file():
            raise FileNotFoundError(path)
        item["body"] = path.read_bytes()
        attached.append(item)
    return attached


def _emit(report: dict, path: str | None) -> None:
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    print(text)


def cmd_inspect(args: argparse.Namespace) -> int:
    entries = load_log(args.log)
    _emit(inspect_log(entries), args.report)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        entries = _attach_bodies(load_log(args.log), args.bodies)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        now_unix = _parse_now(args.now)
        report = verify_log(entries, keys, policy, now_unix)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"load failure: {exc}", file=sys.stderr)
        return 2
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    text = json.dumps(report, ensure_ascii=False, indent=2)
    Path(args.report).write_text(text + "\n", encoding="utf-8")
    print(text)
    decision = report.get("decision")
    if decision == "allow":
        return 0
    if decision == "deny":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="logseal")
    sub = parser.add_subparsers(dest="cmd", required=True)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--log", required=True)
    inspect.add_argument("--report")
    inspect.set_defaults(func=cmd_inspect)

    for name in ("verify", "admit"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--log", required=True)
        cmd.add_argument("--keys", required=True)
        cmd.add_argument("--policy", required=True)
        cmd.add_argument("--now", required=True)
        cmd.add_argument("--report", required=True)
        cmd.add_argument("--bodies")
        cmd.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
