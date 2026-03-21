# CLAUDE.md — PostgreSQL Module

## Overview

Native Mojo PostgreSQL client via libpq FFI. Same pattern as tls/ssl_wrapper.c: thin C shared library (`pg_wrapper.c` -> `libpg_wrapper.so`) re-exports libpq functions under `mojo_pg_*` names.

## Files

| File | Purpose |
|------|---------|
| `pg.mojo` | PgConnection + PgResult structs |
| `pg_wrapper.c` | C shim around libpq (13 functions) |
| `test_pg.mojo` | 9 integration tests |
| `.build_tools/c++` | Linker wrapper injecting -lpg_wrapper |
| `build_and_run.sh` | Build helper (mojo build + run) |

## Build & Run

```bash
pixi run test             # Auto-starts local PG on :15432, runs 9 tests
pixi run init-db          # Initialize .pgdata directory
pixi run start-db         # Start PostgreSQL server
pixi run stop-db          # Stop PostgreSQL server
pixi run compile-pg       # Compile libpg_wrapper.so
```

## API

```mojo
from pg import PgConnection, PgResult

var conn = PgConnection.connect("host=localhost port=15432 dbname=mydb")
var result = conn.exec("SELECT name, score FROM users ORDER BY score DESC")

for row in range(result.num_rows()):
    var name = result.get_value(row, 0)
    var score = result.get_value(row, 1)
    var is_null = result.is_null(row, 1)
    print(name + ": " + score)

result.clear()  # Free PGresult
conn.close()    # Close connection
```

## Key Design Decisions

- **Port 15432** — avoids conflict with any system PostgreSQL on default 5432
- **Trust auth** — test DB uses local trust (no password needed)
- **C string reading** — uses `strlen` + `memcpy` + manual byte copy (no UnsafePointer address constructor in Mojo 0.25.7)
- **All values as String** — matches libpq's PQgetvalue which always returns text
- **Separate .build_tools** — pg has its own linker wrapper (links -lpg_wrapper, not -lssl_wrapper)

## Dependencies

- `libpq` from conda-forge (installed via pixi)
- `postgresql` from conda-forge (for test DB server)
- `mojo 0.25.7`
