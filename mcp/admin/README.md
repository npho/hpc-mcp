# mcp-admin

The MCP admin scripts create API keys to authenticate users against internal MCP servers.

This folder now includes both implementations:

- Python: `mcp-admin.py`
- Go: `mcp-admin.go`

The Python version was the original reference implementation. The Go version provides the same operational workflow for environments where Go is preferred.

The admin script provides command-specific subcommands:

- `create` for key issuance/rotation
- `get` for active-key lookup
- `purge` for cleaning stale rotated keys

### What it does

- Creates an API key for a provided netID username.
- Stores records in an append-only JSONL datastore at
	`api_keys.jsonl` by default.
- Records only three fields per issuance event:
	- `username`
	- `created_at`
	- `api_key`
- Preserves historical keys for the same username (no deletions) upon rotation.

Active-key convention:
- Other programs should treat the most recently created record for a username as the active key.

### Requirements

- Python 3.9+ (3.11+ recommended) for `mcp-admin.py`
- Go 1.22+ recommended for building `mcp-admin.go`

### Usage

The Python and Go CLIs share the same subcommands and datastore format.

```bash
$ python3 mcp-admin.py -h
usage: mcp-admin.py [-h] {create,get,purge} ...

Admin utilities for MCP API key create/get operations.

positional arguments:
	{create,get,purge}
    create      Issue or rotate an API key for a username.
    get         Get active key metadata (latest row) for one or all users.
		purge       Purge stale rotated keys while keeping active keys.

options:
  -h, --help    show this help message and exit
$
```

Build the Go version from this directory:

```bash
go build -o mcp-admin ./mcp-admin.go
./mcp-admin --help
```

Create an API key for a netID.

```bash
python3 mcp-admin.py create <username>
./mcp-admin create <username>
```

Rotate a user key (append a new record) with force.

```bash
python3 mcp-admin.py create <username> --force
# or
python3 mcp-admin.py create <username> -f

./mcp-admin create <username> --force
# or
./mcp-admin create <username> -f
```

Use a custom datastore location:

```bash
python3 mcp-admin.py create <username> --db-file /path/to/api_keys.jsonl
./mcp-admin create <username> --db-file /path/to/api_keys.jsonl
```

### Behavior details

1. If `<username>` does not exist, a new key is issued and appended.
2. If `<username>` already exists and `--force` is not set, the command fails.
3. If `<username>` already exists and `--force` is set, a new key is appended.

This is intentional so key history is retained for auditing and rollback.

### Output

On success, the script prints:

- `username`
- `created_at`
- `api_key`
- `status` (`issued` or `rotated`)
- `db_file`

On error, the script prints an error message to stderr and exits non-zero.

### Datastore format

Each line in `api_keys.jsonl` is one JSON object.

Example:

```json
{"username":"npho","created_at":"2026-03-14T20:43:01.123456Z","api_key":"<redacted>"}
{"username":"npho","created_at":"2026-03-20T09:15:00.000000Z","api_key":"<redacted>"}
```

For username `npho`, the second row is considered active because it is newer.

## Active key lookup CLI

Active key lookup is provided by the same unified script using the `get`
subcommand.

### What it does

- Reads the same datastore (`api_keys.jsonl` by default).
- Returns only active records (latest `created_at` row per username).
- Redacts `api_key` by default to reduce accidental secret exposure.
- Can include raw active keys with `--show-key` if explicitly needed.

### Usage

Get active metadata for one user (safe default, key redacted):

```bash
python3 mcp-admin.py get <username>
./mcp-admin get <username>
```

Get active metadata for all users (one JSON object per line):

```bash
python3 mcp-admin.py get
./mcp-admin get
```

Include raw key material (use cautiously):

```bash
python3 mcp-admin.py get <username> --show-key
./mcp-admin get <username> --show-key
```

Use a custom datastore path:

```bash
python3 mcp-admin.py get --db-file /path/to/api_keys.jsonl
./mcp-admin get --db-file /path/to/api_keys.jsonl
```

## Purge stale rotated keys

The `purge` subcommand scans the datastore for users that have multiple key
records, reports how many stale rotated keys can be removed per user, and then
asks for interactive confirmation before writing changes.

Only stale records are removed. The latest active key for each purged user is
kept.

By default, purge scans all users:

```bash
python3 mcp-admin.py purge
./mcp-admin purge
```

Limit purge scope to one or more usernames:

```bash
python3 mcp-admin.py purge npho alice
./mcp-admin purge npho alice
```

Use a custom datastore path:

```bash
python3 mcp-admin.py purge --db-file /path/to/api_keys.jsonl
./mcp-admin purge --db-file /path/to/api_keys.jsonl
```

Interactive confirmation accepts `Y` or `N` (case-insensitive). Any response
other than `Y` cancels the purge.

### Notes on defaults

- Both implementations use the same JSONL schema.
- The default datastore is `api_keys.jsonl` in this admin directory.
- The Go version is intended to be run from this folder or built from this source file so it resolves the co-located datastore consistently.
