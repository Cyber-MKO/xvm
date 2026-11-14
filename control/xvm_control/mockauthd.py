"""A stand-in for the Wazuh manager's enrollment service (wazuh-authd).

It speaks the agent side of the protocol as Wazuh 4.14.2 sends it
(`src/shared/enrollment_op.c` in the Wazuh source):

| Step | Agent | This service |
| --- | --- | --- |
| 1 | TLS to port 1515 | A self-signed certificate |
| 2 | One request line (below) | Checks the password, if set, and the name |
| 3 | Reads until `OSSEC K:'` or `ERROR: ` | `OSSEC K:'ID NAME IP KEY'`, then closes |
| 4 | Writes `ID NAME IP KEY` to `client.keys` | Logs the request and the key |

The request line is
`[OSSEC PASS: P ]OSSEC A:'NAME'[ V:'vX.Y.Z'][ G:'GROUPS'][ IP:'IP'][ K:'SHA1']`.
The agent checks the manager's certificate only with `<server_ca_path>`.

It is for tests and for checking a host's enrollment without a manager.
It does not run `wazuh-remoted`: after enrolling, the agent's connection
to port 1514 still fails. Every request is a JSON line in `--log`.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

REQUEST = re.compile(
    r"(?:OSSEC PASS: (?P<password>.*?) )?"
    r"OSSEC A:'(?P<name>[^']*)'"
    r"(?: V:'(?P<version>[^']*)')?"
    r"(?: G:'(?P<groups>[^']*)')?"
    r"(?: IP:'(?P<ip>[^']*)')?"
    r"(?: K:'(?P<key_hash>[^']*)')?"
)

# wazuh-authd's rule for agent names: letters, digits, '-', '_', '.'; 2 to 128 long.
NAME = re.compile(r"[A-Za-z0-9._-]{2,128}")


def parse_request(line: str) -> dict | None:
    """The fields of one enrollment request line, or None if it is not one."""
    m = REQUEST.fullmatch(line.rstrip("\r\n"))
    if not m:
        return None
    return {k: v for k, v in m.groupdict().items() if v is not None}


def make_certificate(folder: Path) -> tuple[Path, Path]:
    """A throwaway self-signed certificate and key, made with the openssl tool."""
    cert, key = folder / "authd.cert", folder / "authd.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=xvm-mock-authd", "-days", "2",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert, key


@dataclass
class MockAuthd:
    """The enrollment service. `start()` listens; `stop()` closes."""

    host: str = "127.0.0.1"
    port: int = 1515
    password: str | None = None
    log: Path | None = None
    cert: Path | None = None
    key: Path | None = None
    first_id: int = 1
    requests: list[dict] = field(default_factory=list)
    agents: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._next_id = self.first_id
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._tmp: tempfile.TemporaryDirectory | None = None

    # ------------------------------------------------------------ protocol

    def answer(self, line: str, peer: str) -> tuple[str, dict]:
        """The reply to one request line from `peer`, and the log record."""
        record: dict = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "peer": peer}
        req = parse_request(line)
        if req is None:
            record["error"] = "not an enrollment request"
            record["raw"] = line[:512]
            return "ERROR: Invalid request for new agent\n", record
        record.update({k: v for k, v in req.items() if k != "password"})
        record["password_sent"] = "password" in req
        if self.password is not None and req.get("password") != self.password:
            record["error"] = "invalid password"
            return "ERROR: Invalid password\n", record
        name = req["name"]
        if not NAME.fullmatch(name):
            record["error"] = "invalid agent name"
            return f"ERROR: Invalid agent name: {name}\n", record
        ip = req.get("ip") or "any"
        if ip == "src":
            ip = peer
        with self._lock:
            agent_id = f"{self._next_id:03d}"
            self._next_id += 1
            key = secrets.token_hex(32)
            self.agents[name] = {"id": agent_id, "ip": ip, "key": key}
        entry = f"{agent_id} {name} {ip} {key}"
        record["issued"] = entry
        return f"OSSEC K:'{entry}'\n", record

    def _record(self, record: dict) -> None:
        with self._lock:
            self.requests.append(record)
            if self.log:
                with self.log.open("a") as f:
                    f.write(json.dumps(record) + "\n")

    def _serve_one(self, conn: socket.socket, peer: str, ctx: ssl.SSLContext) -> None:
        try:
            conn.settimeout(30)
            with ctx.wrap_socket(conn, server_side=True) as tls:
                data = b""
                while b"\n" not in data and len(data) < 70000:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                reply, record = self.answer(data.decode("utf-8", "replace"), peer)
                record["tls"] = tls.version()
                tls.sendall(reply.encode())
                self._record(record)
                with contextlib.suppress(OSError, ssl.SSLError):
                    tls.unwrap()
        except (OSError, ssl.SSLError) as e:
            self._record({"peer": peer, "error": f"connection: {e}"})
        finally:
            conn.close()

    # ------------------------------------------------------------ lifecycle

    def start(self) -> int:
        """Listen and serve in a thread. Returns the port (useful with port 0)."""
        if self.cert is None or self.key is None:
            self._tmp = tempfile.TemporaryDirectory(prefix="xvm-authd-")
            self.cert, self.key = make_certificate(Path(self._tmp.name))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        sock = self._sock

        def loop() -> None:
            while True:
                try:
                    conn, addr = sock.accept()
                except OSError:
                    return
                threading.Thread(
                    target=self._serve_one, args=(conn, addr[0], ctx), daemon=True
                ).start()

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._sock:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
            self._sock = None
        if self._thread:
            self._thread.join(timeout=5)
        if self._tmp:
            self._tmp.cleanup()
            self._tmp = None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="xvm-mock-authd",
        description="A stand-in for the Wazuh manager's enrollment service on port 1515.",
    )
    ap.add_argument("--listen", default="127.0.0.1:1515", help="ADDRESS:PORT (default %(default)s)")
    ap.add_argument("--log", type=Path, help="append each request as a JSON line")
    ap.add_argument("--password-file", type=Path, help="require this enrollment password")
    ap.add_argument("--cert", type=Path, help="PEM certificate (default: a throwaway one)")
    ap.add_argument("--key", type=Path, help="PEM key for --cert")
    args = ap.parse_args(argv)
    host, _, port = args.listen.rpartition(":")
    password = None
    if args.password_file:
        password = args.password_file.read_text().splitlines()[0].strip()
    server = MockAuthd(
        host=host.strip("[]") or "0.0.0.0",
        port=int(port),
        password=password,
        log=args.log,
        cert=args.cert,
        key=args.key,
    )
    bound = server.start()
    print(f"xvm-mock-authd listening on {server.host}:{bound}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
