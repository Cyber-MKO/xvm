"""Client for the host-state engine (engine/README.md): length-prefixed JSON over a Unix socket."""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path

MAX_MESSAGE = 16 * 1024 * 1024


class EngineError(Exception):
    """The engine refused a request. `code` is its error code, such as `not_found`."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Engine:
    """One connection, bound to one host."""

    def __init__(self, socket_path: Path | str, host: str):
        self.host = host
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(str(socket_path))
        self._next = 1
        self.hello = self.call("hello", host=host)

    def close(self) -> None:
        self._sock.close()

    def _recv(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("engine closed the connection")
            buf.extend(chunk)
        return bytes(buf)

    def call(self, op: str, **params):
        req_id = self._next
        self._next += 1
        body = json.dumps({"id": req_id, "op": op, **params}).encode()
        self._sock.sendall(struct.pack(">I", len(body)) + body)
        (length,) = struct.unpack(">I", self._recv(4))
        if length > MAX_MESSAGE:
            raise ConnectionError("engine answer too large")
        resp = json.loads(self._recv(length))
        if resp.get("id") != req_id:
            raise ConnectionError(f"answer {resp.get('id')} for request {req_id}")
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise EngineError(err.get("code", "unknown"), err.get("message", ""))
        return resp.get("result")
