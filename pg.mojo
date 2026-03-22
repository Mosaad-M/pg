# ============================================================================
# pg.mojo — PostgreSQL Client via libpq FFI
# ============================================================================
#
# Provides PgConnection and PgResult structs wrapping libpq functions.
#
# libpq calls go through pg_wrapper.c / libpg_wrapper.so because Mojo's
# external_call resolves symbols at link time and mojo build doesn't
# support -l flags. The wrapper is linked via .build_tools/c++ PATH hack.
#
# Usage:
#   var conn = PgConnection.connect("host=localhost dbname=test")
#   var result = conn.exec("SELECT * FROM users")
#   for row in range(result.num_rows()):
#       print(result.get_value(row, 0))
#   result.clear()
#   conn.close()
#
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import UnsafePointer, alloc


# ============================================================================
# libpq status constants
# ============================================================================

alias CONNECTION_OK = 0
alias PGRES_COMMAND_OK = 1
alias PGRES_TUPLES_OK = 2


# ============================================================================
# FFI wrappers (via libpg_wrapper.so)
# ============================================================================


def _pg_connect(conninfo: UnsafePointer[Int8, _]) -> Int:
    """PQconnectdb(conninfo) -> PGconn*."""
    return external_call["mojo_pg_connect", Int](Int(conninfo))


def _pg_status(conn: Int) -> Int32:
    """PQstatus(conn) -> ConnStatusType."""
    return external_call["mojo_pg_status", Int32](conn)


def _pg_error_message(conn: Int) -> Int:
    """PQerrorMessage(conn) -> const char*."""
    return external_call["mojo_pg_error_message", Int](conn)


def _pg_finish(conn: Int):
    """PQfinish(conn)."""
    external_call["mojo_pg_finish", NoneType](conn)


def _pg_exec(conn: Int, query: UnsafePointer[Int8, _]) -> Int:
    """PQexec(conn, query) -> PGresult*."""
    return external_call["mojo_pg_exec", Int](conn, Int(query))


def _pg_result_status(result: Int) -> Int32:
    """PQresultStatus(result) -> ExecStatusType."""
    return external_call["mojo_pg_result_status", Int32](result)


def _pg_result_error_message(result: Int) -> Int:
    """PQresultErrorMessage(result) -> const char*."""
    return external_call["mojo_pg_result_error_message", Int](result)


def _pg_ntuples(result: Int) -> Int32:
    """PQntuples(result) -> int."""
    return external_call["mojo_pg_ntuples", Int32](result)


def _pg_nfields(result: Int) -> Int32:
    """PQnfields(result) -> int."""
    return external_call["mojo_pg_nfields", Int32](result)


def _pg_fname(result: Int, col: Int32) -> Int:
    """PQfname(result, col) -> const char*."""
    return external_call["mojo_pg_fname", Int](result, col)


def _pg_getvalue(result: Int, row: Int32, col: Int32) -> Int:
    """PQgetvalue(result, row, col) -> const char*."""
    return external_call["mojo_pg_getvalue", Int](result, row, col)


def _pg_getisnull(result: Int, row: Int32, col: Int32) -> Int32:
    """PQgetisnull(result, row, col) -> int."""
    return external_call["mojo_pg_getisnull", Int32](result, row, col)


def _pg_clear(result: Int):
    """PQclear(result)."""
    external_call["mojo_pg_clear", NoneType](result)


# ============================================================================
# Helper: read C string into Mojo String
# ============================================================================


def _strlen(ptr: Int) -> Int:
    """Get length of a C string via strlen.

    Args:
        ptr: Address of a null-terminated C string.

    Returns:
        Length in bytes (not including null terminator).
    """
    return external_call["strlen", Int](ptr)


def _cstr_to_string(ptr: Int) -> String:
    """Convert a C string pointer to a Mojo String.

    Args:
        ptr: Address of a null-terminated C string.

    Returns:
        Mojo String copy of the C string. Empty string if ptr is 0.
    """
    if ptr == 0:
        return String("")

    var length = _strlen(ptr)
    if length == 0:
        return String("")

    # Allocate buffer and memcpy from C string
    var buf = alloc[UInt8](length)
    _ = external_call["memcpy", Int](Int(buf), ptr, length)

    var bytes = List[UInt8](capacity=length)
    for i in range(length):
        bytes.append((buf + i)[])
    buf.free()

    return String(unsafe_from_utf8=bytes^)


# ============================================================================
# PgResult — Query Result Container
# ============================================================================


struct PgResult(Movable):
    """Wraps a PGresult pointer. Must be cleared after use."""

    var _result: Int  # PGresult* as opaque pointer

    def __init__(out self, result_ptr: Int):
        """Create from raw PGresult pointer.

        Args:
            result_ptr: Opaque PGresult pointer.
        """
        self._result = result_ptr

    def __moveinit__(out self, deinit take: Self):
        self._result = take._result

    def num_rows(self) -> Int:
        """Number of rows in result.

        Returns:
            Row count.
        """
        return Int(_pg_ntuples(self._result))

    def num_cols(self) -> Int:
        """Number of columns in result.

        Returns:
            Column count.
        """
        return Int(_pg_nfields(self._result))

    def field_name(self, col: Int) -> String:
        """Get column name by index.

        Args:
            col: Column index (0-based).

        Returns:
            Column name string.
        """
        var ptr = _pg_fname(self._result, Int32(col))
        return _cstr_to_string(ptr)

    def get_value(self, row: Int, col: Int) -> String:
        """Get cell value as string.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).

        Returns:
            Cell value as string. Empty string for NULL values.
        """
        var ptr = _pg_getvalue(self._result, Int32(row), Int32(col))
        return _cstr_to_string(ptr)

    def is_null(self, row: Int, col: Int) -> Bool:
        """Check if cell is NULL.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).

        Returns:
            True if the cell is NULL.
        """
        return _pg_getisnull(self._result, Int32(row), Int32(col)) == 1

    def clear(mut self):
        """Free the PGresult. Must be called when done."""
        if self._result != 0:
            _pg_clear(self._result)
            self._result = 0


# ============================================================================
# PgConnection — Database Connection
# ============================================================================


struct PgConnection(Movable):
    """PostgreSQL connection via libpq.

    Usage:
        var conn = PgConnection.connect("host=localhost dbname=test")
        var result = conn.exec("SELECT 1")
        print(result.get_value(0, 0))
        result.clear()
        conn.close()
    """

    var _conn: Int  # PGconn* as opaque pointer

    def __init__(out self):
        """Create unconnected instance."""
        self._conn = 0

    def __moveinit__(out self, deinit take: Self):
        self._conn = take._conn

    @staticmethod
    def connect(conninfo: String) raises -> PgConnection:
        """Connect to PostgreSQL.

        Args:
            conninfo: libpq connection string
                (e.g. "host=localhost dbname=mydb user=postgres").

        Returns:
            Connected PgConnection.

        Raises:
            Error if connection fails.
        """
        var conn_str = conninfo
        var conn_ptr = _pg_connect(conn_str.unsafe_cstr_ptr())

        if conn_ptr == 0:
            raise Error("pg: PQconnectdb returned NULL")

        var status = _pg_status(conn_ptr)
        if status != Int32(CONNECTION_OK):
            var err_ptr = _pg_error_message(conn_ptr)
            var err_msg = _cstr_to_string(err_ptr)
            _pg_finish(conn_ptr)
            raise Error("pg: connection failed: " + err_msg)

        var result = PgConnection()
        result._conn = conn_ptr
        return result^

    def exec(self, query: String) raises -> PgResult:
        """Execute a SQL query.

        Args:
            query: SQL query string.

        Returns:
            PgResult containing the query results.

        Raises:
            Error if query execution fails.
        """
        if self._conn == 0:
            raise Error("pg: not connected")

        var q = query
        var result_ptr = _pg_exec(self._conn, q.unsafe_cstr_ptr())

        if result_ptr == 0:
            raise Error("pg: PQexec returned NULL")

        var status = _pg_result_status(result_ptr)

        # PGRES_COMMAND_OK (1) = successful command with no data
        # PGRES_TUPLES_OK (2) = successful query with data
        if status != Int32(PGRES_COMMAND_OK) and status != Int32(PGRES_TUPLES_OK):
            var err_ptr = _pg_result_error_message(result_ptr)
            var err_msg = _cstr_to_string(err_ptr)
            _pg_clear(result_ptr)
            raise Error("pg: query failed: " + err_msg)

        return PgResult(result_ptr)

    def close(mut self):
        """Close the connection. Safe to call multiple times."""
        if self._conn != 0:
            _pg_finish(self._conn)
            self._conn = 0
