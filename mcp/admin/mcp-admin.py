#!/usr/bin/env python3
"""Unified MCP API key admin CLI.

This utility merges key issuance/rotation and active-key lookup into a single
entrypoint with subcommands:
- create: issue or rotate a key for a username
- get: read active key metadata (latest record per username)
- purge: remove stale rotated keys while keeping active records

Datastore characteristics:
- Local JSONL flat file for operational simplicity
- Append-only writes to preserve full key history
- Exact schema per row: username, created_at, api_key

Active-key convention:
- For a given username, the row with the most recent created_at is active.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Lightweight netID-style username validation.
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

# Keep datastore co-located with the admin CLI scripts.
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = SCRIPT_DIR / "api_keys.jsonl"


@dataclass(frozen=True)
class ApiKeyRecord:
    """One immutable key event row in the datastore."""

    username: str
    created_at: str
    api_key: str

    def to_json_line(self) -> str:
        """Serialize to compact JSON for JSONL append operations."""

        payload = {
            "username": self.username,
            "created_at": self.created_at,
            "api_key": self.api_key,
        }
        return json.dumps(payload, separators=(",", ":"))


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser with command-specific subparsers."""

    parser = argparse.ArgumentParser(
        description="Admin utilities for MCP API key create/get operations."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser(
        "create",
        help="Issue or rotate an API key for a username.",
    )
    create_parser.add_argument(
        "username",
        help="NetID username to issue an API key for (for example: npho).",
    )
    create_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Issue a new key even if the username already has one (rotation).",
    )
    create_parser.add_argument(
        "--db-file",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to JSONL datastore (default: {DEFAULT_DB_PATH}).",
    )

    get_parser = subparsers.add_parser(
        "get",
        help="Get active key metadata (latest row) for one or all users.",
    )
    get_parser.add_argument(
        "username",
        nargs="?",
        help="Optional netID username to query. Omit to list all users.",
    )
    get_parser.add_argument(
        "--show-key",
        action="store_true",
        help="Include raw active API key in output (default is redacted).",
    )
    get_parser.add_argument(
        "--db-file",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to JSONL datastore (default: {DEFAULT_DB_PATH}).",
    )

    purge_parser = subparsers.add_parser(
        "purge",
        help="Purge stale rotated keys while keeping active keys.",
    )
    purge_parser.add_argument(
        "usernames",
        nargs="*",
        help="Optional netID usernames to purge. Omit to scan all users.",
    )
    purge_parser.add_argument(
        "--db-file",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to JSONL datastore (default: {DEFAULT_DB_PATH}).",
    )

    return parser


def resolve_db_path(db_path: Path) -> Path:
    """Resolve datastore path to an absolute normalized location."""

    return db_path.expanduser().resolve()


def validate_username(username: str) -> None:
    """Enforce a practical netID-like username policy."""

    if USERNAME_PATTERN.fullmatch(username):
        return

    raise ValueError(
        "Invalid username. Expected pattern: "
        "start with a lowercase letter, then lowercase letters/digits/_/- "
        "(max 32 chars)."
    )


def utc_now_iso8601() -> str:
    """Return current UTC timestamp in ISO 8601 with Z suffix."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_created_at(created_at: str) -> datetime:
    """Parse ISO 8601 timestamps, including trailing Z form."""

    return datetime.fromisoformat(created_at.replace("Z", "+00:00"))


def generate_api_key() -> str:
    """Generate cryptographically secure URL-safe key material."""

    return secrets.token_urlsafe(32)


def parse_record(raw_line: str, db_path: Path, line_number: int) -> ApiKeyRecord | None:
    """Parse and validate one datastore row.

    Invalid rows are skipped with warnings so one bad line does not block admin
    workflows for otherwise valid records.
    """

    try:
        item = json.loads(raw_line)
    except json.JSONDecodeError:
        print(
            f"Warning: ignored malformed JSON at {db_path}:{line_number}.",
            file=sys.stderr,
        )
        return None

    if not isinstance(item, dict):
        print(
            f"Warning: ignored non-object JSON at {db_path}:{line_number}.",
            file=sys.stderr,
        )
        return None

    required = {"username", "created_at", "api_key"}
    if set(item.keys()) != required:
        print(
            (
                "Warning: ignored row with unexpected schema at "
                f"{db_path}:{line_number}."
            ),
            file=sys.stderr,
        )
        return None

    try:
        username = str(item["username"])
        created_at = str(item["created_at"])
        api_key = str(item["api_key"])
        parse_created_at(created_at)
    except (TypeError, ValueError):
        print(
            (
                "Warning: ignored row with invalid field values at "
                f"{db_path}:{line_number}."
            ),
            file=sys.stderr,
        )
        return None

    return ApiKeyRecord(username=username, created_at=created_at, api_key=api_key)


def username_exists(db_path: Path, username: str) -> bool:
    """Return True if datastore already contains any row for username."""

    if not db_path.exists():
        return False

    with db_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue

            record = parse_record(raw, db_path, line_number)
            if record is not None and record.username == username:
                return True

    return False


def append_record(db_path: Path, record: ApiKeyRecord) -> None:
    """Append one new record to JSONL datastore."""

    db_path.parent.mkdir(parents=True, exist_ok=True)

    with db_path.open("a", encoding="utf-8") as handle:
        handle.write(record.to_json_line())
        handle.write("\n")


def load_active_records(db_path: Path) -> dict[str, ApiKeyRecord]:
    """Load only the active row (latest created_at) per username."""

    active: dict[str, ApiKeyRecord] = {}
    if not db_path.exists():
        return active

    with db_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue

            record = parse_record(raw, db_path, line_number)
            if record is None:
                continue

            current = active.get(record.username)
            if current is None or parse_created_at(record.created_at) > parse_created_at(
                current.created_at
            ):
                active[record.username] = record

    return active


def load_db_entries(db_path: Path) -> list[tuple[str, ApiKeyRecord | None]]:
    """Load datastore rows preserving raw line content and parsed records."""

    entries: list[tuple[str, ApiKeyRecord | None]] = []
    if not db_path.exists():
        return entries

    with db_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw_line = line.rstrip("\n")
            stripped = raw_line.strip()
            if not stripped:
                entries.append((raw_line, None))
                continue

            entries.append((raw_line, parse_record(stripped, db_path, line_number)))

    return entries


def format_get_output(record: ApiKeyRecord, show_key: bool) -> str:
    """Format stable JSON output for get command."""

    payload = {
        "username": record.username,
        "created_at": record.created_at,
        "api_key": record.api_key if show_key else "<redacted>",
    }
    return json.dumps(payload, separators=(",", ":"))


def run_create(args: argparse.Namespace) -> int:
    """Handle create subcommand lifecycle."""

    db_path = resolve_db_path(args.db_file)

    try:
        validate_username(args.username)
        exists = username_exists(db_path, args.username)
        if exists and not args.force:
            raise RuntimeError(
                "Username already exists in datastore. "
                "Use --force (or -f) to rotate and append a new key."
            )

        record = ApiKeyRecord(
            username=args.username,
            created_at=utc_now_iso8601(),
            api_key=generate_api_key(),
        )
        append_record(db_path, record)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: failed to write datastore: {exc}", file=sys.stderr)
        return 1

    print(f"username: {record.username}")
    print(f"created_at: {record.created_at}")
    print(f"api_key: {record.api_key}")
    print("status: rotated" if args.force else "status: issued")
    print(f"db_file: {db_path}")

    return 0


def run_get(args: argparse.Namespace) -> int:
    """Handle get subcommand lifecycle."""

    db_path = resolve_db_path(args.db_file)

    try:
        if args.username is not None:
            validate_username(args.username)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not db_path.exists():
        print(f"Error: datastore not found at {db_path}", file=sys.stderr)
        return 1

    active_records = load_active_records(db_path)

    if args.username is not None:
        record = active_records.get(args.username)
        if record is None:
            print(f"Error: no records found for username {args.username}", file=sys.stderr)
            return 1

        print(format_get_output(record, args.show_key))
        return 0

    for username in sorted(active_records):
        print(format_get_output(active_records[username], args.show_key))

    return 0


def run_purge(args: argparse.Namespace) -> int:
    """Handle purge subcommand lifecycle."""

    db_path = resolve_db_path(args.db_file)

    try:
        for username in args.usernames:
            validate_username(username)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not db_path.exists():
        print(f"Error: datastore not found at {db_path}", file=sys.stderr)
        return 1

    try:
        entries = load_db_entries(db_path)
    except OSError as exc:
        print(f"Error: failed to read datastore: {exc}", file=sys.stderr)
        return 1

    counts: dict[str, int] = {}
    for _, record in entries:
        if record is None:
            continue
        counts[record.username] = counts.get(record.username, 0) + 1

    if args.usernames:
        target_users = set(args.usernames)
    else:
        target_users = set(counts)

    rotated_users = sorted(
        username for username in target_users if counts.get(username, 0) > 1
    )
    total_removable = 0

    if rotated_users:
        print("Users with rotated keys eligible for purge:")
        for username in rotated_users:
            removable = counts[username] - 1
            total_removable += removable
            print(f"- {username}: {removable} rotated keys can be removed")
    else:
        print("No rotated keys found for purge scope.")

    print(f"Total rotated keys removable: {total_removable}")

    if total_removable == 0:
        print("Nothing to purge; exiting without modifying datastore.")
        return 0

    try:
        response = input("Proceed with purge? [Y/N]: ").strip().lower()
    except EOFError:
        response = "n"
    if response != "y":
        print("Purge cancelled.")
        return 0

    keep_index: dict[str, int] = {}
    keep_created_at: dict[str, datetime] = {}
    for index, (_, record) in enumerate(entries):
        if record is None:
            continue
        if record.username not in target_users:
            continue
        if counts.get(record.username, 0) <= 1:
            continue

        record_time = parse_created_at(record.created_at)
        current = keep_created_at.get(record.username)
        if current is None or record_time > current:
            keep_created_at[record.username] = record_time
            keep_index[record.username] = index

    filtered_lines: list[str] = []
    removed = 0
    for index, (raw_line, record) in enumerate(entries):
        if record is None:
            filtered_lines.append(raw_line)
            continue

        if (
            record.username in target_users
            and counts.get(record.username, 0) > 1
            and keep_index.get(record.username) != index
        ):
            removed += 1
            continue

        filtered_lines.append(raw_line)

    temp_path = db_path.with_suffix(f"{db_path.suffix}.tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            for line in filtered_lines:
                handle.write(line)
                handle.write("\n")
        temp_path.replace(db_path)
    except OSError as exc:
        print(f"Error: failed to write datastore: {exc}", file=sys.stderr)
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return 1

    print(f"Purged rotated keys: {removed}")
    print(f"db_file: {db_path}")
    return 0


def main() -> int:
    """CLI entrypoint."""

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "create":
        return run_create(args)
    if args.command == "get":
        return run_get(args)
    if args.command == "purge":
        return run_purge(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
