# test_std_compat.mojo — pg must not break programs that use Mojo's std
#
# A Mojo program may declare each C function with one signature only. std
# declares getenv, clock_gettime, open/read/write and errno access itself.
# pg 1.5.2 declared getenv and clock_gettime with other types (and tls before
# 1.7.0 declared open/read and errno access), so any program combining
# PgConnection with std.os.getenv, open(), listdir() or get_errno() failed
# to compile ("existing function with conflicting signature").
#
# Compiling this file is the test: it reaches PgConnection's connect (SCRAM,
# TLS, USER default) and exec paths together with those std APIs. Running
# it exercises the std calls only.

from std.ffi import get_errno
from std.os import getenv, listdir
from std.sys import argv
from std.time import monotonic, perf_counter_ns
from pg import PgConnection

comptime PATH = "/tmp/mojo_pg_std_compat.txt"


def network_paths() raises:
    """Never run: compiled so that PgConnection's C declarations are present."""
    var c = PgConnection.connect("host=localhost port=5432 dbname=x sslmode=require")
    _ = c.exec("SELECT 1")
    c.close()


def main() raises:
    print("test_std_compat")
    if len(argv()) > 1000:
        network_paths()
    with open(PATH, "w") as f:
        f.write("std open() next to pg\n")
    with open(PATH, "r") as f:
        if not f.read().startswith("std open()"):
            raise Error("std open()/read() round trip failed")
    _ = listdir("/tmp")
    _ = getenv("USER")
    _ = get_errno()
    _ = perf_counter_ns() + monotonic()
    print("  PASS: PgConnection compiles next to std open/listdir/getenv/get_errno/clocks")
    print("Results: 1 passed, 0 failed")
