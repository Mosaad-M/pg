# ============================================================================
# pg.mojo — Pure-Mojo PostgreSQL Client (Wire Protocol v3)
# ============================================================================
#
# Implements the PostgreSQL frontend/backend protocol (PG wire v3) directly
# over TCP, with no C shim and no libpq dependency.
#
# Supported auth methods: trust, cleartext password, MD5 password.
# TLS (sslmode=require) is deferred; connect via plain TCP only.
#
# Public API (unchanged from libpq version):
#   var conn = PgConnection.connect("host=localhost port=15432 dbname=mydb")
#   var result = conn.exec("SELECT name, score FROM users")
#   for row in range(result.num_rows()):
#       print(result.get_value(row, 0))
#   result.clear()
#   conn.close()
#
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc, UnsafePointer
from tcp import TcpSocket


# ============================================================================
# Message type byte constants
# ============================================================================

comptime MSG_AUTH: UInt8 = 82        # 'R'
comptime MSG_PARAM_STATUS: UInt8 = 83  # 'S'
comptime MSG_BACKEND_KEY: UInt8 = 75   # 'K'
comptime MSG_READY: UInt8 = 90         # 'Z'
comptime MSG_ROW_DESC: UInt8 = 84      # 'T'
comptime MSG_DATA_ROW: UInt8 = 68      # 'D'
comptime MSG_COMMAND_COMPLETE: UInt8 = 67  # 'C'
comptime MSG_ERROR: UInt8 = 69         # 'E'
comptime MSG_NOTICE: UInt8 = 78        # 'N'
comptime MSG_EMPTY_QUERY: UInt8 = 73   # 'I'


# ============================================================================
# Big-endian byte helpers
# ============================================================================


def _write_i32(val: Int32) -> List[UInt8]:
    """Encode a 32-bit int as 4 big-endian bytes."""
    var v = UInt32(val)
    var out = List[UInt8](capacity=4)
    out.append(UInt8((v >> 24) & 0xFF))
    out.append(UInt8((v >> 16) & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))
    return out^


def _write_i16(val: Int16) -> List[UInt8]:
    """Encode a 16-bit int as 2 big-endian bytes."""
    var v = UInt16(val)
    var out = List[UInt8](capacity=2)
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))
    return out^


def _read_i32(buf: List[UInt8], offset: Int) -> Int32:
    """Read a 32-bit big-endian int from buf at offset."""
    var b0 = UInt32(buf[offset])
    var b1 = UInt32(buf[offset + 1])
    var b2 = UInt32(buf[offset + 2])
    var b3 = UInt32(buf[offset + 3])
    return Int32((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)


def _read_i16(buf: List[UInt8], offset: Int) -> Int16:
    """Read a 16-bit big-endian int from buf at offset."""
    var b0 = UInt16(buf[offset])
    var b1 = UInt16(buf[offset + 1])
    return Int16((b0 << 8) | b1)


def _read_cstr(buf: List[UInt8], offset: Int) -> Tuple[String, Int]:
    """Read a null-terminated C string from buf at offset.

    Returns:
        (string, next_offset) — next_offset points past the null byte.
    """
    var end = offset
    var n = len(buf)
    while end < n and buf[end] != 0:
        end += 1
    var length = end - offset
    var bytes = List[UInt8](capacity=length)
    for i in range(offset, end):
        bytes.append(buf[i])
    var s = String(unsafe_from_utf8=bytes^)
    return (s^, end + 1)


def _append_str(mut out: List[UInt8], s: String):
    """Append string bytes (without null) to out."""
    var sb = s.as_bytes()
    for i in range(len(sb)):
        out.append(sb[i])


def _append_cstr(mut out: List[UInt8], s: String):
    """Append string bytes followed by a null byte to out."""
    _append_str(out, s)
    out.append(0)


# ============================================================================
# MD5 implementation (RFC 1321)
# ============================================================================
# Used for MD5 authentication: md5(password || username) and
# md5(inner_hex || salt).


def _md5(data: List[UInt8]) -> List[UInt8]:
    """Compute MD5 digest of data. Returns 16 raw bytes."""
    var msg_len = len(data)
    var bit_len = UInt64(msg_len) * 8

    # Copy data, append 0x80, pad to 56 mod 64, append 64-bit LE length
    var padded = List[UInt8](capacity=msg_len + 64 + 8)
    for i in range(msg_len):
        padded.append(data[i])
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0)
    for i in range(8):
        padded.append(UInt8((bit_len >> UInt64(i * 8)) & 0xFF))

    # K constants (floor(abs(sin(i+1)) * 2^32))
    var K = List[UInt32](capacity=64)
    K.append(0xD76AA478); K.append(0xE8C7B756); K.append(0x242070DB); K.append(0xC1BDCEEE)
    K.append(0xF57C0FAF); K.append(0x4787C62A); K.append(0xA8304613); K.append(0xFD469501)
    K.append(0x698098D8); K.append(0x8B44F7AF); K.append(0xFFFF5BB1); K.append(0x895CD7BE)
    K.append(0x6B901122); K.append(0xFD987193); K.append(0xA679438E); K.append(0x49B40821)
    K.append(0xF61E2562); K.append(0xC040B340); K.append(0x265E5A51); K.append(0xE9B6C7AA)
    K.append(0xD62F105D); K.append(0x02441453); K.append(0xD8A1E681); K.append(0xE7D3FBC8)
    K.append(0x21E1CDE6); K.append(0xC33707D6); K.append(0xF4D50D87); K.append(0x455A14ED)
    K.append(0xA9E3E905); K.append(0xFCEFA3F8); K.append(0x676F02D9); K.append(0x8D2A4C8A)
    K.append(0xFFFA3942); K.append(0x8771F681); K.append(0x6D9D6122); K.append(0xFDE5380C)
    K.append(0xA4BEEA44); K.append(0x4BDECFA9); K.append(0xF6BB4B60); K.append(0xBEBFBC70)
    K.append(0x289B7EC6); K.append(0xEAA127FA); K.append(0xD4EF3085); K.append(0x04881D05)
    K.append(0xD9D4D039); K.append(0xE6DB99E5); K.append(0x1FA27CF8); K.append(0xC4AC5665)
    K.append(0xF4292244); K.append(0x432AFF97); K.append(0xAB9423A7); K.append(0xFC93A039)
    K.append(0x655B59C3); K.append(0x8F0CCC92); K.append(0xFFEFF47D); K.append(0x85845DD1)
    K.append(0x6FA87E4F); K.append(0xFE2CE6E0); K.append(0xA3014314); K.append(0x4E0811A1)
    K.append(0xF7537E82); K.append(0xBD3AF235); K.append(0x2AD7D2BB); K.append(0xEB86D391)

    # Per-round shift amounts
    var s = List[UInt32](capacity=64)
    s.append(7);  s.append(12); s.append(17); s.append(22)
    s.append(7);  s.append(12); s.append(17); s.append(22)
    s.append(7);  s.append(12); s.append(17); s.append(22)
    s.append(7);  s.append(12); s.append(17); s.append(22)
    s.append(5);  s.append(9);  s.append(14); s.append(20)
    s.append(5);  s.append(9);  s.append(14); s.append(20)
    s.append(5);  s.append(9);  s.append(14); s.append(20)
    s.append(5);  s.append(9);  s.append(14); s.append(20)
    s.append(4);  s.append(11); s.append(16); s.append(23)
    s.append(4);  s.append(11); s.append(16); s.append(23)
    s.append(4);  s.append(11); s.append(16); s.append(23)
    s.append(4);  s.append(11); s.append(16); s.append(23)
    s.append(6);  s.append(10); s.append(15); s.append(21)
    s.append(6);  s.append(10); s.append(15); s.append(21)
    s.append(6);  s.append(10); s.append(15); s.append(21)
    s.append(6);  s.append(10); s.append(15); s.append(21)

    # Initial hash state
    var a0: UInt32 = 0x67452301
    var b0: UInt32 = 0xEFCDAB89
    var c0: UInt32 = 0x98BADCFE
    var d0: UInt32 = 0x10325476

    # Process each 512-bit (64-byte) block
    var num_blocks = len(padded) // 64
    for blk in range(num_blocks):
        var base = blk * 64
        # Load 16 little-endian UInt32 words
        var M = List[UInt32](capacity=16)
        for j in range(16):
            var o = base + j * 4
            var w = (UInt32(padded[o + 3]) << 24) | (UInt32(padded[o + 2]) << 16) | (UInt32(padded[o + 1]) << 8) | UInt32(padded[o])
            M.append(w)

        var A = a0
        var B = b0
        var C = c0
        var D = d0

        for i in range(64):
            var F: UInt32 = 0
            var g: Int = 0
            if i < 16:
                F = (B & C) | ((~B) & D)
                g = i
            elif i < 32:
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | (~D))
                g = (7 * i) % 16

            var tmp = D
            D = C
            C = B
            var sum32 = A + F + K[i] + M[g]
            var sh = s[i]
            var rotated = (sum32 << sh) | (sum32 >> (UInt32(32) - sh))
            B = B + rotated
            A = tmp

        a0 = a0 + A
        b0 = b0 + B
        c0 = c0 + C
        d0 = d0 + D

    # Output: 4 words in little-endian byte order = 16 bytes
    var digest = List[UInt8](capacity=16)
    for w_idx in range(4):
        var word: UInt32 = 0
        if w_idx == 0:
            word = a0
        elif w_idx == 1:
            word = b0
        elif w_idx == 2:
            word = c0
        else:
            word = d0
        digest.append(UInt8(word & 0xFF))
        digest.append(UInt8((word >> 8) & 0xFF))
        digest.append(UInt8((word >> 16) & 0xFF))
        digest.append(UInt8((word >> 24) & 0xFF))
    return digest^


comptime _HEX_CHARS = "0123456789abcdef"


def _hex_encode(data: List[UInt8]) -> String:
    """Encode bytes as lowercase hex string."""
    var out = List[UInt8](capacity=len(data) * 2)
    var hc = _HEX_CHARS.as_bytes()
    for i in range(len(data)):
        var b = Int(data[i])
        out.append(hc[(b >> 4) & 0xF])
        out.append(hc[b & 0xF])
    return String(unsafe_from_utf8=out^)


def _md5_hex(data: List[UInt8]) -> String:
    """Compute MD5 and return lowercase hex string."""
    return _hex_encode(_md5(data))


def _str_to_bytes(s: String) -> List[UInt8]:
    """Convert String to List[UInt8] (no null terminator)."""
    var sb = s.as_bytes()
    var out = List[UInt8](capacity=len(sb))
    for i in range(len(sb)):
        out.append(sb[i])
    return out^


def _md5_pg_password(password: String, username: String, salt: List[UInt8]) -> String:
    """Compute PostgreSQL MD5 auth response.

    Formula: "md5" + md5_hex(md5_hex(password || username) || salt)
    """
    var inner_data = List[UInt8]()
    _append_str(inner_data, password)
    _append_str(inner_data, username)
    var inner_hex = _md5_hex(inner_data)

    var outer_data = _str_to_bytes(inner_hex)
    for i in range(len(salt)):
        outer_data.append(salt[i])
    var outer_hex = _md5_hex(outer_data)

    return String("md5") + outer_hex


# ============================================================================
# Connection string parser
# ============================================================================


def _get_os_user() -> String:
    """Return the current OS username from the USER environment variable."""
    var key = String("USER")
    var kb = key.as_bytes()
    var n = len(kb)
    var kbuf = alloc[UInt8](n + 1)
    for i in range(n): (kbuf + i)[] = kb[i]
    (kbuf + n)[] = 0
    var ptr = external_call["getenv", Int](Int(kbuf))
    kbuf.free()
    if ptr == 0:
        return String("postgres")
    var length = external_call["strlen", Int](ptr)
    var vbuf = alloc[UInt8](length)
    _ = external_call["memcpy", Int](Int(vbuf), ptr, length)
    var bytes = List[UInt8](capacity=length)
    for i in range(length): bytes.append((vbuf + i)[])
    vbuf.free()
    return String(unsafe_from_utf8=bytes^)


struct ConnParams(Movable):
    """Parsed PostgreSQL connection parameters."""

    var host: String
    var port: Int
    var dbname: String
    var user: String
    var password: String

    def __init__(out self):
        self.host = String("localhost")
        self.port = 5432
        var os_user = _get_os_user()
        self.dbname = os_user.copy()
        self.user = os_user^
        self.password = String("")

    def __moveinit__(out self, deinit take: Self):
        self.host = take.host^
        self.port = take.port
        self.dbname = take.dbname^
        self.user = take.user^
        self.password = take.password^


def _parse_conninfo(conninfo: String) raises -> ConnParams:
    """Parse 'key=value key=value ...' connection string."""
    var params = ConnParams()
    var sb = conninfo.as_bytes()
    var n = len(sb)
    var i = 0

    while i < n:
        # skip whitespace
        while i < n and (sb[i] == UInt8(32) or sb[i] == UInt8(9) or sb[i] == UInt8(10)):
            i += 1
        if i >= n:
            break

        # read key
        var key_start = i
        while i < n and sb[i] != UInt8(61) and sb[i] != UInt8(32) and sb[i] != UInt8(9):
            i += 1
        var key_bytes = List[UInt8]()
        for j in range(key_start, i):
            key_bytes.append(sb[j])
        var key = String(unsafe_from_utf8=key_bytes^)

        if i >= n or sb[i] != UInt8(61):  # '='
            break
        i += 1  # skip '='

        # read value
        var value_bytes = List[UInt8]()
        if i < n and sb[i] == UInt8(39):  # "'"
            i += 1
            while i < n and sb[i] != UInt8(39):
                if sb[i] == UInt8(92) and i + 1 < n:  # backslash
                    i += 1
                value_bytes.append(sb[i])
                i += 1
            if i < n:
                i += 1  # skip closing quote
        else:
            while i < n and sb[i] != UInt8(32) and sb[i] != UInt8(9) and sb[i] != UInt8(10):
                value_bytes.append(sb[i])
                i += 1
        var value = String(unsafe_from_utf8=value_bytes^)

        if key == "host":
            params.host = value^
        elif key == "port":
            params.port = Int(value)
        elif key == "dbname":
            params.dbname = value^
        elif key == "user":
            params.user = value^
        elif key == "password":
            params.password = value^
        # unknown keys (connect_timeout, sslmode, etc.) silently ignored

    return params^


# ============================================================================
# PgResult — Query Result Container
# ============================================================================


struct PgResult(Movable):
    """Holds query results as in-memory rows/columns."""

    var _names: List[String]
    var _rows: List[List[String]]
    var _nulls: List[List[Bool]]
    var _nrows: Int
    var _ncols: Int

    def __init__(out self):
        self._names = List[String]()
        self._rows = List[List[String]]()
        self._nulls = List[List[Bool]]()
        self._nrows = 0
        self._ncols = 0

    def __moveinit__(out self, deinit take: Self):
        self._names = take._names^
        self._rows = take._rows^
        self._nulls = take._nulls^
        self._nrows = take._nrows
        self._ncols = take._ncols

    def num_rows(self) -> Int:
        """Number of rows in result."""
        return self._nrows

    def num_cols(self) -> Int:
        """Number of columns in result."""
        return self._ncols

    def field_name(self, col: Int) raises -> String:
        """Get column name by index (0-based)."""
        if col < 0 or col >= self._ncols:
            raise Error("pg: column index out of range: " + String(col))
        return self._names[col]

    def get_value(self, row: Int, col: Int) raises -> String:
        """Get cell value as string. Returns empty string for NULL."""
        if row < 0 or row >= self._nrows:
            raise Error("pg: row index out of range: " + String(row))
        if col < 0 or col >= self._ncols:
            raise Error("pg: column index out of range: " + String(col))
        return self._rows[row][col]

    def is_null(self, row: Int, col: Int) raises -> Bool:
        """True if cell is NULL."""
        if row < 0 or row >= self._nrows:
            raise Error("pg: row index out of range: " + String(row))
        if col < 0 or col >= self._ncols:
            raise Error("pg: column index out of range: " + String(col))
        return self._nulls[row][col]

    def clear(mut self):
        """No-op in pure-Mojo implementation (memory freed automatically)."""
        pass


# ============================================================================
# PgConnection — Database Connection
# ============================================================================


struct PgConnection(Movable):
    """PostgreSQL connection via wire protocol v3.

    Usage:
        var conn = PgConnection.connect("host=localhost port=15432 dbname=mydb")
        var result = conn.exec("SELECT 1")
        print(result.get_value(0, 0))
        result.clear()
        conn.close()
    """

    var _tcp: TcpSocket
    var _connected: Bool

    def __init__(out self):
        self._tcp = TcpSocket()
        self._connected = False

    def __moveinit__(out self, deinit take: Self):
        self._tcp = take._tcp^
        self._connected = take._connected

    # -------------------------------------------------------------------------
    # Internal: raw I/O
    # -------------------------------------------------------------------------

    def _send_bytes(self, data: List[UInt8]) raises:
        """Write all bytes in data to the socket."""
        var n = len(data)
        if n == 0:
            return
        var buf = alloc[UInt8](n)
        for i in range(n):
            (buf + i)[] = data[i]
        var sent_total = 0
        while sent_total < n:
            var sent = external_call["send", Int](
                self._tcp.fd, Int(buf + sent_total), n - sent_total, Int32(0)
            )
            if sent <= 0:
                buf.free()
                raise Error("pg: send failed")
            sent_total += sent
        buf.free()

    def _recv_msg(self) raises -> Tuple[UInt8, List[UInt8]]:
        """Read one backend message: (type_byte, body_bytes).

        Format: 1 byte type | 4 bytes big-endian length (includes itself) | body
        """
        var header = self._tcp.recv_bytes_exact(5)
        var msg_type = header[0]
        var length = Int(_read_i32(header, 1))
        var body_len = length - 4
        if body_len < 0:
            raise Error("pg: invalid message length: " + String(length))
        var body = List[UInt8]()
        if body_len > 0:
            body = self._tcp.recv_bytes_exact(body_len)
        return (msg_type, body^)

    # -------------------------------------------------------------------------
    # Internal: protocol messages sent by client
    # -------------------------------------------------------------------------

    def _send_startup(self, params: ConnParams) raises:
        """Send StartupMessage (no type byte; first message only)."""
        var body = List[UInt8]()
        # Protocol version 3.0 = 00 03 00 00
        body.append(0); body.append(3); body.append(0); body.append(0)
        _append_cstr(body, "user")
        _append_cstr(body, params.user)
        _append_cstr(body, "database")
        _append_cstr(body, params.dbname)
        body.append(0)  # terminating zero

        var total_len = Int32(len(body) + 4)
        var msg = _write_i32(total_len)
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_password(self, password: String) raises:
        """Send PasswordMessage (type 'p' = 112)."""
        var body = List[UInt8]()
        _append_cstr(body, password)
        var msg = List[UInt8]()
        msg.append(UInt8(112))  # 'p'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_query(self, query: String) raises:
        """Send Query message (type 'Q' = 81)."""
        var body = List[UInt8]()
        _append_cstr(body, query)
        var msg = List[UInt8]()
        msg.append(UInt8(81))  # 'Q'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_terminate(self) raises:
        """Send Terminate message (type 'X' = 88)."""
        var msg = List[UInt8]()
        msg.append(UInt8(88))  # 'X'
        var length = _write_i32(Int32(4))
        for i in range(len(length)):
            msg.append(length[i])
        self._send_bytes(msg)

    # -------------------------------------------------------------------------
    # Internal: parse server messages
    # -------------------------------------------------------------------------

    def _extract_error(self, body: List[UInt8]) -> String:
        """Extract the 'M' (message) field from an ErrorResponse body."""
        var i = 0
        var n = len(body)
        while i < n:
            var field_type = body[i]
            i += 1
            if field_type == 0:
                break
            var start = i
            while i < n and body[i] != 0:
                i += 1
            if field_type == UInt8(77):  # 'M'
                var msg_bytes = List[UInt8]()
                for j in range(start, i):
                    msg_bytes.append(body[j])
                return String(unsafe_from_utf8=msg_bytes^)
            i += 1  # skip null
        return String("unknown error")

    # -------------------------------------------------------------------------
    # Internal: auth handshake
    # -------------------------------------------------------------------------

    def _handle_auth(self, params: ConnParams) raises:
        """Read and respond to auth messages; loop until ReadyForQuery."""
        while True:
            var msg = self._recv_msg()
            var mtype = msg[0]
            var body = msg[1].copy()

            if mtype == MSG_AUTH:
                if len(body) < 4:
                    raise Error("pg: malformed AuthenticationRequest")
                var auth_type = Int(_read_i32(body, 0))
                if auth_type == 0:
                    # AuthenticationOk — continue waiting for ReadyForQuery
                    continue
                elif auth_type == 3:
                    # CleartextPassword
                    self._send_password(params.password)
                elif auth_type == 5:
                    # MD5Password — 4-byte salt at body[4..8]
                    if len(body) < 8:
                        raise Error("pg: MD5 auth: missing salt")
                    var salt = List[UInt8](capacity=4)
                    salt.append(body[4])
                    salt.append(body[5])
                    salt.append(body[6])
                    salt.append(body[7])
                    var response = _md5_pg_password(params.password, params.user, salt)
                    self._send_password(response)
                else:
                    raise Error("pg: unsupported auth method: " + String(auth_type))

            elif mtype == MSG_PARAM_STATUS or mtype == MSG_BACKEND_KEY or mtype == MSG_NOTICE:
                pass  # discard

            elif mtype == MSG_READY:
                return  # connection ready

            elif mtype == MSG_ERROR:
                var err = self._extract_error(body)
                raise Error("pg: auth error: " + err)

            else:
                pass  # skip unknown

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    @staticmethod
    def connect(conninfo: String) raises -> PgConnection:
        """Connect to PostgreSQL using key=value connection string.

        Args:
            conninfo: Space-separated key=value pairs, e.g.
                "host=localhost port=15432 dbname=mydb user=postgres"

        Returns:
            Connected PgConnection.

        Raises:
            Error if TCP connect or authentication fails.
        """
        var params = _parse_conninfo(conninfo)
        var conn = PgConnection()
        conn._tcp.connect(params.host, params.port)
        conn._connected = True
        conn._send_startup(params)
        conn._handle_auth(params)
        return conn^

    def exec(self, query: String) raises -> PgResult:
        """Execute a SQL query and return results.

        Args:
            query: SQL query string.

        Returns:
            PgResult with rows and column metadata.

        Raises:
            Error if not connected or query fails.
        """
        if not self._connected:
            raise Error("pg: not connected")

        self._send_query(query)

        var result = PgResult()
        var got_row_desc = False

        while True:
            var msg = self._recv_msg()
            var mtype = msg[0]
            var body = msg[1].copy()

            if mtype == MSG_ROW_DESC:
                if len(body) < 2:
                    raise Error("pg: malformed RowDescription")
                var ncols = Int(_read_i16(body, 0))
                result._ncols = ncols
                var offset = 2
                for _ in range(ncols):
                    var cstr_res = _read_cstr(body, offset)
                    var col_name = cstr_res[0]
                    offset = cstr_res[1]
                    result._names.append(col_name^)
                    offset += 18  # skip 18 bytes of field metadata
                got_row_desc = True

            elif mtype == MSG_DATA_ROW:
                if not got_row_desc:
                    raise Error("pg: DataRow before RowDescription")
                if len(body) < 2:
                    raise Error("pg: malformed DataRow")
                var ncols = Int(_read_i16(body, 0))
                var offset = 2
                var row_vals = List[String](capacity=ncols)
                var row_nulls = List[Bool](capacity=ncols)
                for _ in range(ncols):
                    if offset + 4 > len(body):
                        raise Error("pg: DataRow truncated")
                    var col_len = Int(_read_i32(body, offset))
                    offset += 4
                    if col_len == -1:
                        row_vals.append(String(""))
                        row_nulls.append(True)
                    else:
                        var val_bytes = List[UInt8](capacity=col_len)
                        for k in range(col_len):
                            val_bytes.append(body[offset + k])
                        offset += col_len
                        row_vals.append(String(unsafe_from_utf8=val_bytes^))
                        row_nulls.append(False)
                result._rows.append(row_vals^)
                result._nulls.append(row_nulls^)
                result._nrows += 1

            elif mtype == MSG_COMMAND_COMPLETE:
                pass  # query finished, wait for ReadyForQuery

            elif mtype == MSG_READY:
                return result^

            elif mtype == MSG_ERROR:
                var err = self._extract_error(body)
                raise Error("pg: query error: " + err)

            elif mtype == MSG_PARAM_STATUS or mtype == MSG_NOTICE or mtype == MSG_EMPTY_QUERY:
                pass  # discard

            else:
                pass  # skip unknown

    def close(mut self):
        """Close the connection. Safe to call multiple times."""
        if self._connected:
            try:
                self._send_terminate()
            except:
                pass
            self._tcp.close()
            self._connected = False
