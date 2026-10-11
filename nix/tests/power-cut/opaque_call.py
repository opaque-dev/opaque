"""Minimal opaqued IPC client for machine tests.

Sends the v1 handshake and one request over the daemon's Unix socket using
the same framing as the CLI (4-byte big-endian length prefix), then prints the
JSON response. With --hold-open the connection stays open after sending so a
long-running request remains attached to its caller until the machine dies.
"""

import argparse
import json
import socket
import struct
import sys
import time


def send_frame(sock, value):
    data = json.dumps(value).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def read_exact(sock, size):
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            raise ConnectionError("daemon closed the connection")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--hold-open", action="store_true")
    parser.add_argument("method")
    parser.add_argument("params")
    args = parser.parse_args()
    with open(args.token_file, encoding="utf-8") as handle:
        token = handle.read().strip()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.socket)
    send_frame(sock, {"handshake": "v1", "daemon_token": token})
    send_frame(sock, {"id": 1, "method": args.method, "params": json.loads(args.params)})
    if args.hold_open:
        while True:
            time.sleep(3600)
    (length,) = struct.unpack(">I", read_exact(sock, 4))
    json.dump(json.loads(read_exact(sock, length)), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
