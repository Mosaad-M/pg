# ============================================================================
# test_pg.mojo — PostgreSQL Client Integration Tests
# ============================================================================
#
# Tests connect to a local PostgreSQL on port 15432 (managed by pixi tasks).
# Run: pixi run test (auto-starts DB if needed)
# ============================================================================

from pg import PgConnection, PgResult
from pg import _sha256, _hmac_sha256, _b64_encode, _b64_decode, _pbkdf2_sha256


# ============================================================================
# Test helpers
# ============================================================================

comptime CONNINFO = "host=localhost port=15432 dbname=mojo_test"


def assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True, got False")


def assert_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(label + ": expected '" + expected + "', got '" + actual + "'")


def assert_int_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


# ============================================================================
# Tests
# ============================================================================


def test_connect() raises:
    """Connect and disconnect."""
    var conn = PgConnection.connect(CONNINFO)
    conn.close()


def test_connect_bad_conninfo() raises:
    """Bad connection string raises error."""
    var got_error = False
    try:
        var conn = PgConnection.connect("host=localhost port=99999 dbname=nonexistent connect_timeout=1")
        conn.close()
    except:
        got_error = True
    assert_true(got_error, "bad conninfo should raise")


def test_select_one() raises:
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


def test_create_insert_query_drop() raises:
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


def test_null_values() raises:
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


def test_multiple_queries() raises:
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


def test_bad_query() raises:
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


def test_multi_row_query() raises:
    """Query returning multiple rows."""
    var conn = PgConnection.connect(CONNINFO)

    var r1 = conn.exec("SELECT generate_series(1, 5) AS n")
    assert_int_eq(r1.num_rows(), 5, "5 rows from generate_series")
    assert_eq(r1.get_value(0, 0), "1", "row 0")
    assert_eq(r1.get_value(4, 0), "5", "row 4")
    r1.clear()

    conn.close()


def test_data_types() raises:
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


def test_exec_params() raises:
    """exec_params() with $1/$2 placeholders avoids SQL injection."""
    var conn = PgConnection.connect(CONNINFO)

    # Create table (drop first for idempotency)
    var r0 = conn.exec("DROP TABLE IF EXISTS test_params")
    r0.clear()
    var r1 = conn.exec(
        "CREATE TABLE test_params (id INT, name TEXT)"
    )
    r1.clear()
    var r2 = conn.exec("INSERT INTO test_params VALUES (1, 'Alice'), (2, 'Bob')")
    r2.clear()

    # Parameterized query
    var params = List[String]()
    params.append("1")
    var result = conn.exec_params(
        "SELECT id, name FROM test_params WHERE id = $1", params
    )
    assert_int_eq(result.num_rows(), 1, "exec_params rows")
    assert_eq(result.get_value(0, 0), "1", "exec_params id")
    assert_eq(result.get_value(0, 1), "Alice", "exec_params name")
    result.clear()

    # Confirm $2 also works
    var params2 = List[String]()
    params2.append("2")
    params2.append("Bob")
    var result2 = conn.exec_params(
        "SELECT name FROM test_params WHERE id=$1 AND name=$2", params2
    )
    assert_int_eq(result2.num_rows(), 1, "exec_params 2 params")
    assert_eq(result2.get_value(0, 0), "Bob", "exec_params name2")
    result2.clear()

    var r3 = conn.exec("DROP TABLE test_params")
    r3.clear()
    conn.close()


def test_sha256_vectors() raises:
    """SHA-256 known test vectors (FIPS 180-4)."""
    # SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    var empty = List[UInt8]()
    var h0 = _sha256(empty)
    assert_eq(
        _hex_encode_test(h0),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 empty"
    )

    # SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    var abc = List[UInt8]()
    abc.append(UInt8(ord("a"))); abc.append(UInt8(ord("b"))); abc.append(UInt8(ord("c")))
    var h1 = _sha256(abc)
    assert_eq(
        _hex_encode_test(h1),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256 abc"
    )


def test_b64_roundtrip() raises:
    """base64 encode then decode returns original bytes."""
    var data = List[UInt8]()
    for i in range(16):
        data.append(UInt8(i))
    var encoded = _b64_encode(data)
    var decoded = _b64_decode(encoded)
    assert_int_eq(len(decoded), 16, "b64 roundtrip length")
    for i in range(16):
        assert_int_eq(Int(decoded[i]), i, "b64 roundtrip byte " + String(i))


def _hex_encode_test(data: List[UInt8]) -> String:
    """Hex-encode for test assertions."""
    var out = List[UInt8](capacity=len(data) * 2)
    var hc = "0123456789abcdef".as_bytes()
    for i in range(len(data)):
        var b = Int(data[i])
        out.append(hc[(b >> 4) & 0xF])
        out.append(hc[b & 0xF])
    return String(unsafe_from_utf8=out^)


def test_sslmode_parsed() raises:
    """sslmode=require triggers TLS code path; fails on non-TLS server."""
    var got_error = False
    try:
        var conn = PgConnection.connect(
            "host=localhost port=15432 dbname=mojo_test sslmode=require"
        )
        conn.close()
    except e:
        # Expected: TLS handshake fails because local test DB has no TLS cert.
        got_error = True
    assert_true(got_error, "sslmode=require should fail on non-TLS server")


def test_exec_pipeline() raises:
    """Pipeline: 3 INSERTs + 1 SELECT in one round-trip."""
    var conn = PgConnection.connect(
        "host=localhost port=15432 dbname=mojo_test"
    )
    _ = conn.exec("DROP TABLE IF EXISTS test_pipeline")
    _ = conn.exec("CREATE TABLE test_pipeline (id INT, val TEXT)")

    var queries = List[String]()
    queries.append("INSERT INTO test_pipeline VALUES (1, 'alpha')")
    queries.append("INSERT INTO test_pipeline VALUES (2, 'beta')")
    queries.append("INSERT INTO test_pipeline VALUES (3, 'gamma')")
    queries.append("SELECT COUNT(*) FROM test_pipeline")

    var results = conn.exec_pipeline(queries)

    assert_int_eq(len(results), 4, "pipeline: result count")
    assert_true(results[0].error == "", "pipeline: insert 1 no error")
    assert_true(results[1].error == "", "pipeline: insert 2 no error")
    assert_true(results[2].error == "", "pipeline: insert 3 no error")
    assert_true(results[3].error == "", "pipeline: SELECT no error")
    assert_int_eq(results[3].num_rows(), 1, "pipeline: SELECT row count")
    assert_true(results[3].get_value(0, 0) == "3", "pipeline: SELECT count = 3")

    _ = conn.exec("DROP TABLE IF EXISTS test_pipeline")
    conn.close()


def test_exec_pipeline_empty() raises:
    """Empty pipeline returns empty result list."""
    var conn = PgConnection.connect(
        "host=localhost port=15432 dbname=mojo_test"
    )
    var queries = List[String]()
    var results = conn.exec_pipeline(queries)
    assert_int_eq(len(results), 0, "empty pipeline: result count")
    conn.close()


def test_exec_pipeline_single() raises:
    """Single-query pipeline behaves like exec()."""
    var conn = PgConnection.connect(
        "host=localhost port=15432 dbname=mojo_test"
    )
    var queries = List[String]()
    queries.append("SELECT 42 AS n")
    var results = conn.exec_pipeline(queries)
    assert_int_eq(len(results), 1, "single pipeline: result count")
    assert_true(results[0].error == "", "single pipeline: no error")
    assert_int_eq(results[0].num_rows(), 1, "single pipeline: row count")
    assert_true(results[0].get_value(0, 0) == "42", "single pipeline: value")
    conn.close()


def test_exec_pipeline_error_middle() raises:
    """Mixed pipeline: ok, INVALID SQL, ok — middle result has error."""
    var conn = PgConnection.connect(
        "host=localhost port=15432 dbname=mojo_test"
    )
    var queries = List[String]()
    queries.append("SELECT 1 AS first")
    queries.append("INVALID SQL *** DELIBERATE ERROR ***")
    queries.append("SELECT 3 AS third")

    var results = conn.exec_pipeline(queries)
    assert_int_eq(len(results), 3, "mixed pipeline: result count")
    assert_true(results[0].error == "", "mixed pipeline: first ok")
    assert_true(results[1].error != "", "mixed pipeline: second has error")
    # After an error in a pipeline, PG sends ErrorResponse for subsequent
    # queries too. We verify all 3 results are returned (connection still alive).
    conn.close()


def main() raises:
    var passed = 0
    var failed = 0

    def run_test(
        name: String,
        mut passed: Int,
        mut failed: Int,
        test_fn: def () raises -> None,
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
    run_test("sslmode parsed", passed, failed, test_sslmode_parsed)
    run_test("exec_params", passed, failed, test_exec_params)
    run_test("sha256 vectors", passed, failed, test_sha256_vectors)
    run_test("b64 roundtrip", passed, failed, test_b64_roundtrip)
    run_test("exec_pipeline 3 inserts + SELECT", passed, failed, test_exec_pipeline)
    run_test("exec_pipeline empty",              passed, failed, test_exec_pipeline_empty)
    run_test("exec_pipeline single query",       passed, failed, test_exec_pipeline_single)
    run_test("exec_pipeline error in middle",    passed, failed, test_exec_pipeline_error_middle)

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
