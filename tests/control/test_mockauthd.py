"""xvm-mock-authd: the enrollment protocol as the Wazuh 4.14.2 agent speaks it."""

from __future__ import annotations

import json
import re
import shutil
import socket
import ssl

import pytest

from xvm_control.mockauthd import MockAuthd, parse_request

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl tool")


def enroll(port: int, line: str) -> str:
    """What the agent does: TLS without checking the certificate, one line, read to EOF."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
        ctx.wrap_socket(raw) as tls,
    ):
        tls.sendall(line.encode())
        out = b""
        while True:
            try:
                chunk = tls.recv(4096)
            except ssl.SSLEOFError:
                break
            if not chunk:
                break
            out += chunk
    return out.decode()


@pytest.fixture
def authd(tmp_path):
    server = MockAuthd(port=0, log=tmp_path / "authd.jsonl")
    server.start()
    yield server
    server.stop()


def test_parse_request_fields():
    assert parse_request("OSSEC A:'XVM-WIN-01' V:'v4.14.2'\n") == {
        "name": "XVM-WIN-01",
        "version": "v4.14.2",
    }
    assert parse_request(
        "OSSEC PASS: s3cret word OSSEC A:'h1' V:'v4.14.2' G:'default,web' IP:'src' K:'ab12'\n"
    ) == {
        "password": "s3cret word",
        "name": "h1",
        "version": "v4.14.2",
        "groups": "default,web",
        "ip": "src",
        "key_hash": "ab12",
    }
    assert parse_request("GET / HTTP/1.1\n") is None


def test_enrollment_gives_a_key_and_logs_it(authd, tmp_path):
    reply = enroll(authd.port, "OSSEC A:'XVM-WIN-01' V:'v4.14.2'\n")
    m = re.fullmatch(r"OSSEC K:'(\d{3}) (\S+) (\S+) ([0-9a-f]{64})'\n", reply)
    assert m, reply
    assert m.group(1, 2, 3) == ("001", "XVM-WIN-01", "any")
    log = [json.loads(x) for x in (tmp_path / "authd.jsonl").read_text().splitlines()]
    assert log[0]["name"] == "XVM-WIN-01"
    assert log[0]["version"] == "v4.14.2"
    assert log[0]["issued"] == reply[9:-2]
    assert log[0]["password_sent"] is False
    # The next agent gets the next ID; IP:'src' becomes the peer's address.
    reply = enroll(authd.port, "OSSEC A:'second' IP:'src'\n")
    assert reply.startswith("OSSEC K:'002 second 127.0.0.1 ")


def test_password_and_name_errors(tmp_path):
    server = MockAuthd(port=0, password="topsecret")
    server.start()
    try:
        assert enroll(server.port, "OSSEC A:'h1'\n") == "ERROR: Invalid password\n"
        wrong = enroll(server.port, "OSSEC PASS: wrong OSSEC A:'h1'\n")
        assert wrong == "ERROR: Invalid password\n"
        assert enroll(server.port, "OSSEC PASS: topsecret OSSEC A:'h1'\n").startswith(
            "OSSEC K:'001 h1 any "
        )
        assert enroll(server.port, "OSSEC PASS: topsecret OSSEC A:'bad name'\n") == (
            "ERROR: Invalid agent name: bad name\n"
        )
        assert enroll(server.port, "hello\n") == "ERROR: Invalid request for new agent\n"
    finally:
        server.stop()
    assert [r.get("error") for r in server.requests] == [
        "invalid password",
        "invalid password",
        None,
        "invalid agent name",
        "not an enrollment request",
    ]
