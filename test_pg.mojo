# ============================================================================
# test_pg.mojo — PostgreSQL Client Integration Tests
# ============================================================================
#
# Tests connect to a local PostgreSQL on port 15432 (managed by pixi tasks).
# Run: pixi run test (auto-starts DB if needed)
# ============================================================================

from pg import PgConnection, PgResult


# ============================================================================
# Test helpers
# ============================================================================

alias CONNINFO = "host=localhost port=15432 dbname=mojo_test"


fn assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True, got False")


fn assert_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected '" + expected + "', got '" + actual + "'")


fn assert_int_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


# ============================================================================
# Tests
# ============================================================================


fn test_connect() raises:
    """Connect and disconnect."""
    var conn = PgConnection.connect(CONNINFO)
    conn.close()


fn test_connect_bad_conninfo() raises:
    """Bad connection string raises error."""
    var got_error = False
    try:
        var conn = PgConnection.connect("host=localhost port=99999 dbname=nonexistent connect_timeout=1")
        conn.close()
    except:
        got_error = True
    assert_true(got_error, "bad conninfo should raise")


fn test_select_one() raises:
    """SELECT 1 returns correct value."""
    var conn = PgConnection.connect(CONNINFO)
    var result = conn.exec("SELECT 1 AS num")
    assert_int_eq(result.num_rows(), 1, "rows")
    assert_int_eq(result.num_cols(), 1, "cols")
    assert_eq(result.field_name(0), "num", "field name")
    assert_eq(result.get_value(0, 0), "1", "value")
    assert_true(not result.is_null(0, 0), "not null")
    result.clear()
    conn.close()


fn test_create_insert_query_drop() raises:
    """Full lifecycle: CREATE TABLE, INSERT, SELECT, DROP."""
    var conn = PgConnection.connect(CONNINFO)

    # Create
    var r1 = conn.exec(
        "CREATE TABLE IF NOT EXISTS test_mojo ("
        "  id SERIAL PRIMARY KEY,"
        "  name VARCHAR(100) NOT NULL,"
        "  score NUMERIC(5,2)"
        ")"
    )
    r1.clear()

    # Insert
    var r2 = conn.exec("INSERT INTO test_mojo (name, score) VALUES ('Alice', 95.5)")
    r2.clear()
    var r3 = conn.exec("INSERT INTO test_mojo (name, score) VALUES ('Bob', 87.0)")
    r3.clear()

    # Query
    var result = conn.exec("SELECT name, score FROM test_mojo ORDER BY name")
    assert_int_eq(result.num_rows(), 2, "inserted rows")
    assert_int_eq(result.num_cols(), 2, "cols")
    assert_eq(result.get_value(0, 0), "Alice", "row 0 name")
    assert_eq(result.get_value(0, 1), "95.50", "row 0 score")
    assert_eq(result.get_value(1, 0), "Bob", "row 1 name")
    result.clear()

    # Drop
    var r4 = conn.exec("DROP TABLE test_mojo")
    r4.clear()

    conn.close()


fn test_null_values() raises:
    """NULL values detected correctly."""
    var conn = PgConnection.connect(CONNINFO)

    var r1 = conn.exec("CREATE TABLE IF NOT EXISTS test_nulls (a TEXT, b TEXT)")
    r1.clear()
    var r2 = conn.exec("INSERT INTO test_nulls VALUES ('hello', NULL)")
    r2.clear()

    var result = conn.exec("SELECT a, b FROM test_nulls")
    assert_true(not result.is_null(0, 0), "a not null")
    assert_true(result.is_null(0, 1), "b is null")
    assert_eq(result.get_value(0, 0), "hello", "a value")
    result.clear()

    var r3 = conn.exec("DROP TABLE test_nulls")
    r3.clear()

    conn.close()


fn test_multiple_queries() raises:
    """Execute multiple queries on same connection."""
    var conn = PgConnection.connect(CONNINFO)

    var r1 = conn.exec("SELECT 1 AS a")
    assert_eq(r1.get_value(0, 0), "1", "query 1")
    r1.clear()

    var r2 = conn.exec("SELECT 2 AS b")
    assert_eq(r2.get_value(0, 0), "2", "query 2")
    r2.clear()

    var r3 = conn.exec("SELECT 'hello' AS greeting")
    assert_eq(r3.get_value(0, 0), "hello", "query 3")
    r3.clear()

    conn.close()


fn test_bad_query() raises:
    """Invalid SQL raises error."""
    var conn = PgConnection.connect(CONNINFO)
    var got_error = False
    try:
        var result = conn.exec("INVALID SQL GIBBERISH")
        result.clear()
    except:
        got_error = True
    assert_true(got_error, "bad SQL should raise")
    conn.close()


fn test_multi_row_query() raises:
    """Query returning multiple rows."""
    var conn = PgConnection.connect(CONNINFO)

    var r1 = conn.exec("SELECT generate_series(1, 5) AS n")
    assert_int_eq(r1.num_rows(), 5, "5 rows from generate_series")
    assert_eq(r1.get_value(0, 0), "1", "row 0")
    assert_eq(r1.get_value(4, 0), "5", "row 4")
    r1.clear()

    conn.close()


fn test_data_types() raises:
    """Various PostgreSQL data types returned as strings."""
    var conn = PgConnection.connect(CONNINFO)

    var result = conn.exec(
        "SELECT 42::int, 3.14::float, true::bool, 'text'::text,"
        " '2026-02-18'::date"
    )
    assert_eq(result.get_value(0, 0), "42", "int")
    assert_true("3.14" in result.get_value(0, 1), "float")
    assert_eq(result.get_value(0, 2), "t", "bool")
    assert_eq(result.get_value(0, 3), "text", "text")
    assert_eq(result.get_value(0, 4), "2026-02-18", "date")
    result.clear()

    conn.close()


# ============================================================================
# Main
# ============================================================================


fn main() raises:
    var passed = 0
    var failed = 0

    fn run_test(
        name: String,
        mut passed: Int,
        mut failed: Int,
        test_fn: fn () raises -> None,
    ):
        try:
            test_fn()
            print("  PASS:", name)
            passed += 1
        except e:
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== PostgreSQL Client Tests ===")
    print("(connecting to localhost:15432/mojo_test)")
    print()

    run_test("connect", passed, failed, test_connect)
    run_test("bad conninfo", passed, failed, test_connect_bad_conninfo)
    run_test("SELECT 1", passed, failed, test_select_one)
    run_test("create/insert/query/drop", passed, failed, test_create_insert_query_drop)
    run_test("null values", passed, failed, test_null_values)
    run_test("multiple queries", passed, failed, test_multiple_queries)
    run_test("bad query", passed, failed, test_bad_query)
    run_test("multi-row query", passed, failed, test_multi_row_query)
    run_test("data types", passed, failed, test_data_types)

    print()
    print(
        "Results: "
        + String(passed)
        + " passed, "
        + String(failed)
        + " failed, "
        + String(passed + failed)
        + " total"
    )
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
