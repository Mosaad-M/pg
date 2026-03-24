# ============================================================================
# pg.mojo — Pure-Mojo PostgreSQL Client (Wire Protocol v3)
# ============================================================================
#
# Implements the PostgreSQL frontend/backend protocol (PG wire v3) directly
# over TCP, with no C shim and no libpq dependency.
#
# Supported auth methods: trust, cleartext password, MD5 password, SCRAM-SHA-256.
# Supported TLS: sslmode=require or sslmode=verify-full uses TlsSocket.
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
from tls.socket import TlsSocket, load_system_ca_bundle


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
# SHA-256 / HMAC-SHA-256 / PBKDF2 / Base64 (for SCRAM-SHA-256 auth)
# ============================================================================


def _rotr32(x: UInt32, n: UInt32) -> UInt32:
    """Rotate right 32-bit integer x by n bits."""
    return (x >> n) | (x << (UInt32(32) - n))


def _sha256(data: List[UInt8]) -> List[UInt8]:
    """Compute SHA-256 digest (FIPS 180-4). Returns 32 bytes."""
    # K constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    var K = List[UInt32](capacity=64)
    K.append(0x428a2f98); K.append(0x71374491); K.append(0xb5c0fbcf); K.append(0xe9b5dba5)
    K.append(0x3956c25b); K.append(0x59f111f1); K.append(0x923f82a4); K.append(0xab1c5ed5)
    K.append(0xd807aa98); K.append(0x12835b01); K.append(0x243185be); K.append(0x550c7dc3)
    K.append(0x72be5d74); K.append(0x80deb1fe); K.append(0x9bdc06a7); K.append(0xc19bf174)
    K.append(0xe49b69c1); K.append(0xefbe4786); K.append(0x0fc19dc6); K.append(0x240ca1cc)
    K.append(0x2de92c6f); K.append(0x4a7484aa); K.append(0x5cb0a9dc); K.append(0x76f988da)
    K.append(0x983e5152); K.append(0xa831c66d); K.append(0xb00327c8); K.append(0xbf597fc7)
    K.append(0xc6e00bf3); K.append(0xd5a79147); K.append(0x06ca6351); K.append(0x14292967)
    K.append(0x27b70a85); K.append(0x2e1b2138); K.append(0x4d2c6dfc); K.append(0x53380d13)
    K.append(0x650a7354); K.append(0x766a0abb); K.append(0x81c2c92e); K.append(0x92722c85)
    K.append(0xa2bfe8a1); K.append(0xa81a664b); K.append(0xc24b8b70); K.append(0xc76c51a3)
    K.append(0xd192e819); K.append(0xd6990624); K.append(0xf40e3585); K.append(0x106aa070)
    K.append(0x19a4c116); K.append(0x1e376c08); K.append(0x2748774c); K.append(0x34b0bcb5)
    K.append(0x391c0cb3); K.append(0x4ed8aa4a); K.append(0x5b9cca4f); K.append(0x682e6ff3)
    K.append(0x748f82ee); K.append(0x78a5636f); K.append(0x84c87814); K.append(0x8cc70208)
    K.append(0x90befffa); K.append(0xa4506ceb); K.append(0xbef9a3f7); K.append(0xc67178f2)

    # Pad message: append 0x80, zero-pad to 56 mod 64, append 64-bit big-endian length
    var msg_len = len(data)
    var bit_len = UInt64(msg_len) * 8
    var padded = List[UInt8](capacity=msg_len + 128)
    for i in range(msg_len):
        padded.append(data[i])
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0)
    for i in range(8):
        padded.append(UInt8((bit_len >> UInt64((7 - i) * 8)) & 0xFF))

    # Initial hash values
    var h0: UInt32 = 0x6a09e667; var h1: UInt32 = 0xbb67ae85
    var h2: UInt32 = 0x3c6ef372; var h3: UInt32 = 0xa54ff53a
    var h4: UInt32 = 0x510e527f; var h5: UInt32 = 0x9b05688c
    var h6: UInt32 = 0x1f83d9ab; var h7: UInt32 = 0x5be0cd19

    var num_blocks = len(padded) // 64
    for blk in range(num_blocks):
        var base = blk * 64
        # Build message schedule W[0..63]
        var W = List[UInt32](capacity=64)
        for j in range(16):
            var o = base + j * 4
            W.append(
                (UInt32(padded[o]) << 24)
                | (UInt32(padded[o + 1]) << 16)
                | (UInt32(padded[o + 2]) << 8)
                | UInt32(padded[o + 3])
            )
        for j in range(16, 64):
            var s0 = _rotr32(W[j - 15], 7) ^ _rotr32(W[j - 15], 18) ^ (W[j - 15] >> 3)
            var s1 = _rotr32(W[j - 2], 17) ^ _rotr32(W[j - 2], 19) ^ (W[j - 2] >> 10)
            W.append(W[j - 16] + s0 + W[j - 7] + s1)

        var a = h0; var b = h1; var c = h2; var d = h3
        var e = h4; var f = h5; var g = h6; var h = h7

        for i in range(64):
            var S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            var ch = (e & f) ^ ((~e) & g)
            var temp1 = h + S1 + ch + K[i] + W[i]
            var S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            var maj = (a & b) ^ (a & c) ^ (b & c)
            var temp2 = S0 + maj
            h = g; g = f; f = e; e = d + temp1
            d = c; c = b; b = a; a = temp1 + temp2

        h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d
        h4 = h4 + e; h5 = h5 + f; h6 = h6 + g; h7 = h7 + h

    # Output 32 big-endian bytes
    var digest = List[UInt8](capacity=32)
    for wi in range(8):
        var w: UInt32 = 0
        if wi == 0: w = h0
        elif wi == 1: w = h1
        elif wi == 2: w = h2
        elif wi == 3: w = h3
        elif wi == 4: w = h4
        elif wi == 5: w = h5
        elif wi == 6: w = h6
        else: w = h7
        digest.append(UInt8((w >> 24) & 0xFF))
        digest.append(UInt8((w >> 16) & 0xFF))
        digest.append(UInt8((w >> 8) & 0xFF))
        digest.append(UInt8(w & 0xFF))
    return digest^


def _hmac_sha256(key: List[UInt8], data: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA-256. Returns 32 bytes."""
    # Normalize key: hash if > 64 bytes, pad with zeros if < 64 bytes
    var k = List[UInt8](capacity=64)
    if len(key) > 64:
        var hk = _sha256(key)
        for i in range(len(hk)):
            k.append(hk[i])
    else:
        for i in range(len(key)):
            k.append(key[i])
    while len(k) < 64:
        k.append(0)

    # inner = SHA-256((k XOR ipad) || data)
    var inner = List[UInt8](capacity=64 + len(data))
    for i in range(64):
        inner.append(k[i] ^ 0x36)
    for i in range(len(data)):
        inner.append(data[i])
    var inner_hash = _sha256(inner)

    # outer = SHA-256((k XOR opad) || inner_hash)
    var outer = List[UInt8](capacity=96)
    for i in range(64):
        outer.append(k[i] ^ 0x5C)
    for i in range(32):
        outer.append(inner_hash[i])
    return _sha256(outer)^


def _pbkdf2_sha256(
    password: List[UInt8], salt: List[UInt8], iterations: Int
) -> List[UInt8]:
    """PBKDF2-HMAC-SHA-256 with one 32-byte output block."""
    # U1 = HMAC(password, salt || 0x00000001)
    var salt_block = List[UInt8](capacity=len(salt) + 4)
    for i in range(len(salt)):
        salt_block.append(salt[i])
    salt_block.append(0); salt_block.append(0)
    salt_block.append(0); salt_block.append(1)

    var U = _hmac_sha256(password, salt_block)
    var result = U.copy()

    for _ in range(iterations - 1):
        U = _hmac_sha256(password, U)
        var xored = List[UInt8](capacity=32)
        for i in range(32):
            xored.append(result[i] ^ U[i])
        result = xored^

    return result^


comptime _B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _b64_encode(data: List[UInt8]) -> String:
    """Encode bytes as standard base64 (with = padding)."""
    var out = List[UInt8]()
    var chars = _B64_CHARS.as_bytes()
    var n = len(data)
    var i = 0
    while i + 2 < n:
        var b0 = Int(data[i])
        var b1 = Int(data[i + 1])
        var b2 = Int(data[i + 2])
        out.append(chars[(b0 >> 2) & 0x3F])
        out.append(chars[((b0 & 0x3) << 4) | ((b1 >> 4) & 0xF)])
        out.append(chars[((b1 & 0xF) << 2) | ((b2 >> 6) & 0x3)])
        out.append(chars[b2 & 0x3F])
        i += 3
    if i + 1 == n:
        var b0 = Int(data[i])
        out.append(chars[(b0 >> 2) & 0x3F])
        out.append(chars[(b0 & 0x3) << 4])
        out.append(UInt8(ord("=")))
        out.append(UInt8(ord("=")))
    elif i + 2 == n:
        var b0 = Int(data[i])
        var b1 = Int(data[i + 1])
        out.append(chars[(b0 >> 2) & 0x3F])
        out.append(chars[((b0 & 0x3) << 4) | ((b1 >> 4) & 0xF)])
        out.append(chars[(b1 & 0xF) << 2])
        out.append(UInt8(ord("=")))
    return String(unsafe_from_utf8=out^)


def _b64_char_val(c: UInt8) -> Int:
    """Return 6-bit value for a base64 character (0 for '=' or invalid)."""
    if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
        return Int(c) - ord("A")
    elif c >= UInt8(ord("a")) and c <= UInt8(ord("z")):
        return Int(c) - ord("a") + 26
    elif c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return Int(c) - ord("0") + 52
    elif c == UInt8(ord("+")):
        return 62
    elif c == UInt8(ord("/")):
        return 63
    return 0


def _b64_decode(s: String) -> List[UInt8]:
    """Decode standard base64 string to bytes."""
    var out = List[UInt8]()
    var sb = s.as_bytes()
    var n = len(sb)
    var i = 0
    while i + 4 <= n:
        var c0 = _b64_char_val(sb[i])
        var c1 = _b64_char_val(sb[i + 1])
        var c2 = _b64_char_val(sb[i + 2])
        var c3 = _b64_char_val(sb[i + 3])
        out.append(UInt8((c0 << 2) | (c1 >> 4)))
        if sb[i + 2] != UInt8(ord("=")):
            out.append(UInt8(((c1 & 0xF) << 4) | (c2 >> 2)))
        if sb[i + 3] != UInt8(ord("=")):
            out.append(UInt8(((c2 & 0x3) << 6) | c3))
        i += 4
    return out^


def _random_bytes(n: Int) -> List[UInt8]:
    """Generate n pseudo-random bytes from clock_gettime + PID + SHA-256.

    Sufficient for SCRAM nonces: security is guaranteed by the server's
    additional random contribution to the combined nonce.
    """
    # Read monotonic clock (16 bytes: int64 tv_sec + int64 tv_nsec)
    var ts = alloc[UInt8](16)
    for i in range(16):
        (ts + i)[] = 0
    _ = external_call["clock_gettime", Int32](Int32(1), ts)  # CLOCK_MONOTONIC=1
    var pid = external_call["getpid", Int32]()
    # Seed: clock bytes + PID bytes
    var seed = List[UInt8](capacity=20)
    for i in range(16):
        seed.append((ts + i)[])
    ts.free()
    seed.append(UInt8(Int(pid) & 0xFF))
    seed.append(UInt8((Int(pid) >> 8) & 0xFF))
    seed.append(UInt8((Int(pid) >> 16) & 0xFF))
    seed.append(UInt8((Int(pid) >> 24) & 0xFF))
    # Expand to n bytes via iterated SHA-256
    var result = List[UInt8](capacity=n)
    var counter = 0
    while len(result) < n:
        var ext = seed.copy()
        ext.append(UInt8(counter & 0xFF))
        var hash = _sha256(ext)
        for i in range(len(hash)):
            if len(result) < n:
                result.append(hash[i])
        counter += 1
    return result^


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
    var sslmode: String  # "disable" | "require" | "verify-full"

    def __init__(out self):
        self.host = String("localhost")
        self.port = 5432
        var os_user = _get_os_user()
        self.dbname = os_user.copy()
        self.user = os_user^
        self.password = String("")
        self.sslmode = String("disable")

    def __moveinit__(out self, deinit take: Self):
        self.host = take.host^
        self.port = take.port
        self.dbname = take.dbname^
        self.user = take.user^
        self.password = take.password^
        self.sslmode = take.sslmode^


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
        elif key == "sslmode":
            params.sslmode = value^
        # other unknown keys silently ignored

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
    var _tls: TlsSocket
    var _use_tls: Bool
    var _connected: Bool

    def __init__(out self):
        self._tcp = TcpSocket()
        self._tls = TlsSocket()
        self._use_tls = False
        self._connected = False

    def __moveinit__(out self, deinit take: Self):
        self._tcp = take._tcp^
        self._tls = take._tls^
        self._use_tls = take._use_tls
        self._connected = take._connected

    # -------------------------------------------------------------------------
    # Internal: raw I/O
    # -------------------------------------------------------------------------

    def _send_bytes(mut self, data: List[UInt8]) raises:
        """Write all bytes in data to the socket."""
        if self._use_tls:
            var sent = 0
            while sent < len(data):
                var chunk = List[UInt8]()
                for i in range(sent, len(data)):
                    chunk.append(data[i])
                var n = self._tls.send(chunk)
                sent += n
            return
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

    def _recv_msg(mut self) raises -> Tuple[UInt8, List[UInt8]]:
        """Read one backend message: (type_byte, body_bytes).

        Format: 1 byte type | 4 bytes big-endian length (includes itself) | body
        """
        var header: List[UInt8]
        if self._use_tls:
            header = self._tls.recv_exact(5)
        else:
            header = self._tcp.recv_bytes_exact(5)
        var msg_type = header[0]
        var length = Int(_read_i32(header, 1))
        var body_len = length - 4
        if body_len < 0:
            raise Error("pg: invalid message length: " + String(length))
        var body = List[UInt8]()
        if body_len > 0:
            if self._use_tls:
                body = self._tls.recv_exact(body_len)
            else:
                body = self._tcp.recv_bytes_exact(body_len)
        return (msg_type, body^)

    # -------------------------------------------------------------------------
    # Internal: protocol messages sent by client
    # -------------------------------------------------------------------------

    def _send_startup(mut self, params: ConnParams) raises:
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

    def _send_password(mut self, password: String) raises:
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

    def _send_query(mut self, query: String) raises:
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

    def _send_parse(mut self, query: String) raises:
        """Send Parse message (type 'P' = 80). Uses unnamed statement."""
        var body = List[UInt8]()
        _append_cstr(body, "")     # unnamed statement
        _append_cstr(body, query)  # query string
        var nparams = _write_i16(Int16(0))  # no parameter type OIDs
        for i in range(len(nparams)):
            body.append(nparams[i])
        var msg = List[UInt8]()
        msg.append(UInt8(80))  # 'P'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_bind(mut self, params: List[String]) raises:
        """Send Bind message (type 'B' = 66). Text format for all params/results."""
        var body = List[UInt8]()
        _append_cstr(body, "")  # unnamed portal
        _append_cstr(body, "")  # unnamed statement
        var nfmt = _write_i16(Int16(0))  # zero format codes = use text for all
        for i in range(len(nfmt)):
            body.append(nfmt[i])
        var np = _write_i16(Int16(len(params)))
        for i in range(len(np)):
            body.append(np[i])
        for pi in range(len(params)):
            var pb = _str_to_bytes(params[pi])
            var plen = _write_i32(Int32(len(pb)))
            for i in range(len(plen)):
                body.append(plen[i])
            for i in range(len(pb)):
                body.append(pb[i])
        var rfc = _write_i16(Int16(0))  # zero result format codes = text
        for i in range(len(rfc)):
            body.append(rfc[i])
        var msg = List[UInt8]()
        msg.append(UInt8(66))  # 'B'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_describe_portal(mut self) raises:
        """Send Describe portal message (type 'D' = 68). Triggers RowDescription."""
        var body = List[UInt8]()
        body.append(UInt8(80))  # 'P' = portal (vs 'S' = statement)
        _append_cstr(body, "")  # unnamed portal
        var msg = List[UInt8]()
        msg.append(UInt8(68))  # 'D'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_execute(mut self) raises:
        """Send Execute message (type 'E' = 69). Unnamed portal, unlimited rows."""
        var body = List[UInt8]()
        _append_cstr(body, "")   # unnamed portal
        var rl = _write_i32(Int32(0))  # no row limit
        for i in range(len(rl)):
            body.append(rl[i])
        var msg = List[UInt8]()
        msg.append(UInt8(69))  # 'E'
        var length = _write_i32(Int32(len(body) + 4))
        for i in range(len(length)):
            msg.append(length[i])
        for i in range(len(body)):
            msg.append(body[i])
        self._send_bytes(msg)

    def _send_sync(mut self) raises:
        """Send Sync message (type 'S' = 83)."""
        var msg = List[UInt8]()
        msg.append(UInt8(83))  # 'S'
        var length = _write_i32(Int32(4))
        for i in range(len(length)):
            msg.append(length[i])
        self._send_bytes(msg)

    def _send_terminate(mut self) raises:
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

    def _do_scram_auth(mut self, body: List[UInt8], params: ConnParams) raises:
        """Handle SCRAM-SHA-256 authentication exchange (RFC 5802).

        Called from _handle_auth when auth_type == 10 (SASL).
        Manages all SCRAM round-trips internally; on return, _handle_auth
        will receive AuthenticationOk then ReadyForQuery as normal.

        Args:
            body: Body of the initial AuthenticationSASL message (auth_type + mechs).
            params: Connection parameters with user/password.
        """
        # Verify SCRAM-SHA-256 is in the mechanism list
        var found_scram = False
        var i = 4  # skip Int32(10)
        while i < len(body):
            var mend = i
            while mend < len(body) and body[mend] != 0:
                mend += 1
            if mend > i:
                var mb = List[UInt8]()
                for j in range(i, mend):
                    mb.append(body[j])
                if String(unsafe_from_utf8=mb^) == "SCRAM-SHA-256":
                    found_scram = True
            i = mend + 1

        if not found_scram:
            raise Error("pg: SCRAM-SHA-256 not offered by server")

        # Generate client nonce (18 random bytes → base64)
        var nonce_raw = _random_bytes(18)
        var client_nonce = _b64_encode(nonce_raw)

        # client-first-message
        var client_first_bare = "n=" + params.user + ",r=" + client_nonce
        var client_first = "n,," + client_first_bare

        # Send SASLInitialResponse ('p')
        var payload = List[UInt8]()
        _append_cstr(payload, "SCRAM-SHA-256")
        var cfb = _str_to_bytes(client_first)
        var cflen = _write_i32(Int32(len(cfb)))
        for k in range(4):
            payload.append(cflen[k])
        for k in range(len(cfb)):
            payload.append(cfb[k])
        var sasl_init = List[UInt8]()
        sasl_init.append(UInt8(112))  # 'p'
        var sasl_len = _write_i32(Int32(len(payload) + 4))
        for k in range(4):
            sasl_init.append(sasl_len[k])
        for k in range(len(payload)):
            sasl_init.append(payload[k])
        self._send_bytes(sasl_init)

        # Receive AuthenticationSASLContinue (auth_type 11)
        var msg2 = self._recv_msg()
        if msg2[0] != MSG_AUTH:
            raise Error("pg: SCRAM: expected SASLContinue")
        var b2 = msg2[1].copy()
        if len(b2) < 4 or Int(_read_i32(b2, 0)) != 11:
            raise Error("pg: SCRAM: expected auth_type 11")

        # Parse server-first-message: "r=<nonce>,s=<salt_b64>,i=<iter>"
        var sf_bytes = List[UInt8]()
        for k in range(4, len(b2)):
            sf_bytes.append(b2[k])
        var server_first = String(unsafe_from_utf8=sf_bytes^)

        var server_nonce = String("")
        var salt_b64 = String("")
        var iterations = 4096

        var sf_raw = server_first.as_bytes()
        var sf_n = len(sf_raw)
        var pos = 0
        while pos < sf_n:
            var eq = pos
            while eq < sf_n and sf_raw[eq] != UInt8(ord("=")):
                eq += 1
            if eq >= sf_n:
                break
            var kb = List[UInt8]()
            for k in range(pos, eq):
                kb.append(sf_raw[k])
            var sf_key = String(unsafe_from_utf8=kb^)
            eq += 1
            var vs = eq
            while eq < sf_n and sf_raw[eq] != UInt8(ord(",")):
                eq += 1
            var vb = List[UInt8]()
            for k in range(vs, eq):
                vb.append(sf_raw[k])
            var sf_val = String(unsafe_from_utf8=vb^)
            if sf_key == "r":
                server_nonce = sf_val^
            elif sf_key == "s":
                salt_b64 = sf_val^
            elif sf_key == "i":
                iterations = Int(sf_val)
            pos = eq + 1  # skip ','

        if len(server_nonce) == 0 or len(salt_b64) == 0:
            raise Error("pg: SCRAM: malformed server-first: " + server_first)

        # Verify server nonce starts with our client nonce
        var cn_b = client_nonce.as_bytes()
        var sn_b = server_nonce.as_bytes()
        if len(sn_b) < len(cn_b):
            raise Error("pg: SCRAM: server nonce shorter than client nonce")
        for k in range(len(cn_b)):
            if sn_b[k] != cn_b[k]:
                raise Error("pg: SCRAM: server nonce mismatch")

        # Compute SaltedPassword = PBKDF2-HMAC-SHA-256(password, salt, iterations)
        var salt = _b64_decode(salt_b64)
        var pw_bytes = _str_to_bytes(params.password)
        var salted_pw = _pbkdf2_sha256(pw_bytes, salt, iterations)

        # ClientKey = HMAC(SaltedPassword, "Client Key")
        var client_key = _hmac_sha256(salted_pw, _str_to_bytes("Client Key"))
        # StoredKey = SHA-256(ClientKey)
        var stored_key = _sha256(client_key)

        # client-final-message-without-proof
        var gs2_b64 = _b64_encode(_str_to_bytes("n,,"))
        var cfm_no_proof = "c=" + gs2_b64 + ",r=" + server_nonce

        # AuthMessage = client-first-bare + "," + server-first + "," + cfm-no-proof
        var auth_msg = _str_to_bytes(
            client_first_bare + "," + server_first + "," + cfm_no_proof
        )

        # ClientSignature = HMAC(StoredKey, AuthMessage)
        var client_sig = _hmac_sha256(stored_key, auth_msg)

        # ClientProof = ClientKey XOR ClientSignature
        var client_proof = List[UInt8](capacity=32)
        for k in range(32):
            client_proof.append(client_key[k] ^ client_sig[k])
        var proof_b64 = _b64_encode(client_proof)

        # ServerSignature = HMAC(HMAC(SaltedPassword, "Server Key"), AuthMessage)
        var server_key = _hmac_sha256(salted_pw, _str_to_bytes("Server Key"))
        var expected_server_sig = _b64_encode(_hmac_sha256(server_key, auth_msg))

        # Send SASLResponse ('p') with client-final-message
        var client_final = cfm_no_proof + ",p=" + proof_b64
        var cf_bytes = _str_to_bytes(client_final)
        var sasl_resp = List[UInt8]()
        sasl_resp.append(UInt8(112))  # 'p'
        var resp_len = _write_i32(Int32(len(cf_bytes) + 4))
        for k in range(4):
            sasl_resp.append(resp_len[k])
        for k in range(len(cf_bytes)):
            sasl_resp.append(cf_bytes[k])
        self._send_bytes(sasl_resp)

        # Receive AuthenticationSASLFinal (auth_type 12)
        var msg3 = self._recv_msg()
        if msg3[0] != MSG_AUTH:
            raise Error("pg: SCRAM: expected SASLFinal")
        var b3 = msg3[1].copy()
        if len(b3) < 4 or Int(_read_i32(b3, 0)) != 12:
            raise Error("pg: SCRAM: expected auth_type 12")

        # Verify server signature: body is "v=<base64>"
        var sf_final_b = List[UInt8]()
        for k in range(4, len(b3)):
            sf_final_b.append(b3[k])
        var server_final = String(unsafe_from_utf8=sf_final_b^)
        var sf_raw2 = server_final.as_bytes()
        if len(sf_raw2) > 2 and sf_raw2[0] == UInt8(ord("v")) and sf_raw2[1] == UInt8(ord("=")):
            var sig_b = List[UInt8]()
            for k in range(2, len(sf_raw2)):
                sig_b.append(sf_raw2[k])
            var actual_sig = String(unsafe_from_utf8=sig_b^)
            if actual_sig != expected_server_sig:
                raise Error("pg: SCRAM: server signature verification failed")

    # -------------------------------------------------------------------------
    # Internal: auth handshake
    # -------------------------------------------------------------------------

    def _handle_auth(mut self, params: ConnParams) raises:
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
                elif auth_type == 10:
                    # SASL — SCRAM-SHA-256 (handles all SCRAM round-trips internally)
                    self._do_scram_auth(body, params)
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
        if params.sslmode == "require" or params.sslmode == "verify-full":
            var cas = load_system_ca_bundle()
            conn._tls = TlsSocket(conn._tcp.fd)
            conn._tls.connect(params.host, cas)
            conn._use_tls = True
        conn._connected = True
        conn._send_startup(params)
        conn._handle_auth(params)
        return conn^

    def exec(mut self, query: String) raises -> PgResult:
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

    def exec_params(mut self, query: String, params: List[String]) raises -> PgResult:
        """Execute a parameterized query using the Extended Query protocol.

        Uses $1, $2, ... placeholders. Parameters are sent as text values,
        avoiding manual SQL quoting and injection risk.

        Args:
            query: SQL with $N placeholders, e.g. "SELECT * FROM t WHERE id=$1".
            params: Parameter values as strings.

        Returns:
            PgResult with rows and column metadata.

        Raises:
            Error if not connected or query fails.
        """
        if not self._connected:
            raise Error("pg: not connected")

        self._send_parse(query)
        self._send_bind(params)
        self._send_describe_portal()
        self._send_execute()
        self._send_sync()

        var result = PgResult()
        var got_row_desc = False

        while True:
            var msg = self._recv_msg()
            var mtype = msg[0]
            var body = msg[1].copy()

            if mtype == UInt8(49) or mtype == UInt8(50):
                # ParseComplete ('1') or BindComplete ('2') — discard
                pass
            elif mtype == MSG_ROW_DESC:
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
                    offset += 18
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
            elif mtype == MSG_COMMAND_COMPLETE or mtype == UInt8(110):
                # CommandComplete or NoData — continue
                pass
            elif mtype == MSG_READY:
                return result^
            elif mtype == MSG_ERROR:
                var err = self._extract_error(body)
                raise Error("pg: exec_params error: " + err)
            elif mtype == MSG_PARAM_STATUS or mtype == MSG_NOTICE or mtype == MSG_EMPTY_QUERY:
                pass
            else:
                pass

    def close(mut self):
        """Close the connection. Safe to call multiple times."""
        if self._connected:
            try:
                self._send_terminate()
            except:
                pass
            if self._use_tls:
                try:
                    self._tls.close()
                except:
                    pass
            self._tcp.close()
            self._connected = False
