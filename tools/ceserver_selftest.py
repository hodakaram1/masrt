#!/usr/bin/env python3
"""
CEServer self-test client.

Mimics the exact Cheat Engine client handshake for the process list so you can
verify the Imno CoServer bridge without launching Cheat Engine:

  1. CMD_GETVERSION (0)                  -> version + name string
  2. CMD_CREATETOOLHELP32SNAPSHOTEX (35) -> 4-byte handle for TH32CS_SNAPPROCESS
  3. CMD_PROCESS32FIRST (5) / CMD_PROCESS32NEXT (6) -> streamed process entries
  4. CMD_CLOSEHANDLE (7)

Run it while Imno's CoServer tab shows the server as RUNNING:

    python tools/ceserver_selftest.py 127.0.0.1 52736

If step 2 returns a handle of 0 (or this script times out), the bug is inside
the server; otherwise the server enumerates processes correctly and the
problem is elsewhere (e.g. a stale Imno.exe build).
"""

import socket
import struct
import sys


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                "connection closed after %d/%d bytes (%r...)" % (len(data), n, data[:32])
            )
        data += chunk
    return data


def send_exact(sock, data):
    sock.sendall(data)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 52736
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    try:
        # 1. GETVERSION -----------------------------------------------------
        send_exact(sock, b"\x00")
        version = struct.unpack("<i", recv_exact(sock, 4))[0]
        (stringsize,) = struct.unpack("<B", recv_exact(sock, 1))
        name = recv_exact(sock, stringsize).decode("latin-1")
        print(f"[GETVERSION] version={version} name={name!r}")
        assert version >= 6, f"server version {version} < 6 (Cheat Engine will reject it)"

        # 2. SNAPSHOTEX (TH32CS_SNAPPROCESS) --------------------------------
        TH32CS_SNAPPROCESS = 0x2
        send_exact(sock, b"\x23" + struct.pack("<II", TH32CS_SNAPPROCESS, 0))  # cmd 35
        handle = struct.unpack("<i", recv_exact(sock, 4))[0]
        print(f"[SNAPSHOTEX] handle={handle:#x}")
        assert handle != 0, "BUG: snapshot returned handle 0 -> CE reports 'windows NT' error"

        # 3. enumerate processes --------------------------------------------
        names = []
        cmd_first, cmd_next = 5, 6
        for first in (True, False):
            cmd = cmd_first if first else cmd_next
            while True:
                send_exact(sock, bytes([cmd]) + struct.pack("<I", handle & 0xFFFFFF))
                result, pid, namesize = struct.unpack("<iiI", recv_exact(sock, 12))
                if not result:
                    break
                pname = recv_exact(sock, namesize).decode("latin-1")
                names.append((pid, pname))
                if first:
                    break
        print(f"[PROCESS32*] got {len(names)} processes")
        for pid, pname in names[:10]:
            print(f"    {pid:8d}  {pname}")
        if len(names) > 10:
            print(f"    ... and {len(names)-10} more")

        # 4. close handle ---------------------------------------------------
        send_exact(sock, b"\x07" + struct.pack("<I", handle & 0xFFFFFF))
        (closed,) = struct.unpack("<i", recv_exact(sock, 4))
        print(f"[CLOSEHANDLE] result={closed}")

        print("\nOK: server returned a valid snapshot handle and enumerated processes.")
        print("    If Cheat Engine still fails, rebuild Imno (build.bat) and check the")
        print("    CoServer 'Log' panel for the exact command sequence.")
        return 0
    except (AssertionError, ConnectionError) as e:
        print(f"\nFAIL: {e}", file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
