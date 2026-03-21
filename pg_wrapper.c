/* ============================================================================
 * pg_wrapper.c — Thin C shim around libpq for Mojo FFI
 * ============================================================================
 *
 * Same pattern as tls/ssl_wrapper.c: Mojo's external_call resolves symbols
 * at link/JIT time. Since mojo build has no -l flags, this shared library
 * re-exports libpq functions under mojo_pg_* names.
 *
 * Build:
 *   gcc -shared -fPIC -o libpg_wrapper.so pg_wrapper.c \
 *       -L.pixi/envs/default/lib -lpq -I.pixi/envs/default/include \
 *       -Wl,-rpath,'$ORIGIN/.pixi/envs/default/lib'
 *
 * ============================================================================ */

#include <libpq-fe.h>
#include <string.h>

/* ---------- Connection management ---------- */

void* mojo_pg_connect(const char* conninfo) {
    return (void*)PQconnectdb(conninfo);
}

int mojo_pg_status(void* conn) {
    return (int)PQstatus((PGconn*)conn);
}

const char* mojo_pg_error_message(void* conn) {
    return PQerrorMessage((PGconn*)conn);
}

void mojo_pg_finish(void* conn) {
    PQfinish((PGconn*)conn);
}

/* ---------- Query execution ---------- */

void* mojo_pg_exec(void* conn, const char* query) {
    return (void*)PQexec((PGconn*)conn, query);
}

int mojo_pg_result_status(void* result) {
    return (int)PQresultStatus((PGresult*)result);
}

const char* mojo_pg_result_error_message(void* result) {
    return PQresultErrorMessage((PGresult*)result);
}

/* ---------- Result inspection ---------- */

int mojo_pg_ntuples(void* result) {
    return PQntuples((PGresult*)result);
}

int mojo_pg_nfields(void* result) {
    return PQnfields((PGresult*)result);
}

const char* mojo_pg_fname(void* result, int col) {
    return PQfname((PGresult*)result, col);
}

const char* mojo_pg_getvalue(void* result, int row, int col) {
    return PQgetvalue((PGresult*)result, row, col);
}

int mojo_pg_getisnull(void* result, int row, int col) {
    return PQgetisnull((PGresult*)result, row, col);
}

/* ---------- Cleanup ---------- */

void mojo_pg_clear(void* result) {
    PQclear((PGresult*)result);
}
