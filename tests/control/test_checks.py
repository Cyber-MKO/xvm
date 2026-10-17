"""T2 and T3 against a fake Wazuh manager API."""

from __future__ import annotations

import base64
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from xvm_control import checks, profile
from xvm_control.checkcli import main
from xvm_control.manager import Manager, ManagerError

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "control" / "profiles" / "examples"
T0 = datetime(2026, 10, 17, 10, 0, tzinfo=UTC)


class FakeManager:
    """Serves /security/user/authenticate and /agents like the Wazuh API."""

    def __init__(self):
        self.agent: dict | None = None
        self.tokens_issued = 0
        self.expire_next = False
        self.logins = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                ok = base64.b64encode(b"wazuh:secret").decode()
                if self.path != "/security/user/authenticate":
                    return self._send(404, {})
                if self.headers.get("Authorization") != f"Basic {ok}":
                    return self._send(401, {"title": "Unauthorized"})
                fake.logins += 1
                fake.tokens_issued += 1
                self._send(200, {"data": {"token": f"t{fake.tokens_issued}"}, "error": 0})

            def do_GET(self):
                if (
                    self.headers.get("Authorization") != f"Bearer t{fake.tokens_issued}"
                    or fake.expire_next
                ):
                    fake.expire_next = False
                    return self._send(401, {"title": "Unauthorized"})
                if not self.path.startswith("/agents?"):
                    return self._send(404, {})
                items = [fake.agent] if fake.agent else []
                self._send(
                    200,
                    {
                        "data": {"affected_items": items, "total_affected_items": len(items)},
                        "error": 0,
                    },
                )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def fake():
    f = FakeManager()
    yield f
    f.server.shutdown()


def agent(status="active", keepalive=T0, **os_fields):
    return {
        "id": "007",
        "name": "WIN-WEB-01",
        "status": status,
        "lastKeepAlive": keepalive.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": "Wazuh v4.14.2",
        "os": {
            "name": "Microsoft Windows Server 2022 Standard Evaluation",
            "version": "10.0.20348.1",
            "platform": "windows",
            **os_fields,
        },
    }


def test_client_logs_in_and_renews_its_token(fake):
    fake.agent = agent()
    m = Manager(fake.url, "wazuh", "secret")
    assert m.agent("WIN-WEB-01")["id"] == "007"
    assert m.agent("nobody") is None
    fake.expire_next = True
    assert m.agent("WIN-WEB-01")["status"] == "active"
    assert fake.logins == 2
    with pytest.raises(ManagerError, match="login refused"):
        Manager(fake.url, "wazuh", "wrong").agent("x")


class Clock:
    def __init__(self):
        self.t = T0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += timedelta(seconds=s)


def test_t2_passes_a_steady_day(fake, tmp_path):
    clock = Clock()
    statuses = iter(["never_connected", "pending"] + ["active"] * 100_000)

    class Live(Manager):
        def agent(self, name):
            st = next(statuses)
            return agent(st, keepalive=clock.t - timedelta(seconds=20))

    live = Live(fake.url, "wazuh", "secret")
    log = tmp_path / "t2.jsonl"
    r = checks.watch_t2(
        live, "WIN-WEB-01", 24 * 3600, 60, 600, 120, log, now=clock.now, sleep=clock.sleep
    )
    assert r.passed, r.text()
    assert r.summary["enrolled_after_s"] == 120
    assert r.summary["disconnects"] == 0
    assert r.summary["observed_s"] == 24 * 3600
    # The log rescores to the same result.
    again = checks.score_t2(checks.read_samples(log), 24 * 3600, 120, 60, 600)
    assert again.to_json() == r.to_json()


def _samples(*rows):
    return [{"time": checks._fmt(T0 + timedelta(seconds=t)), **s} for t, s in rows]


def _ka(t):
    return {"status": "active", "last_keepalive": checks._fmt(T0 + timedelta(seconds=t))}


@pytest.mark.parametrize(
    "rows, problem",
    [
        ([(0, {"status": "pending"})], "never active"),
        (
            [(0, _ka(0)), (60, {"status": "disconnected"}), (120, _ka(120)), (180, _ka(180))],
            "not active at",
        ),
        ([(0, _ka(0)), (60, _ka(0)), (120, _ka(0)), (180, _ka(180))], "keepalive was 120"),
        ([(0, _ka(0)), (60, _ka(60))], "watched 60 s of 180 s"),
        ([(0, _ka(0)), (60, _ka(60)), (180, _ka(180))], "no sample for 120 s"),
        (
            [
                (0, {"status": "pending"}),
                (900, _ka(900)),
                (960, _ka(960)),
                (1020, _ka(1020)),
                (1080, _ka(1080)),
            ],
            "active only after 900",
        ),
    ],
)
def test_t2_failures(rows, problem):
    # A 30 s interval: a gap over 90 s is a blind spot.
    r = checks.score_t2(_samples(*rows), 180, 100, 30, 600)
    assert not r.passed
    assert any(problem in p for p in r.problems), r.text()


def test_t2_api_errors_are_counted_not_disconnects():
    rows = [
        (0, _ka(0)),
        (60, {"error": "GET /agents: timed out"}),
        (120, _ka(120)),
        (180, _ka(180)),
    ]
    r = checks.score_t2(_samples(*rows), 180, 100, 60, 600)
    assert r.passed, r.text()
    assert r.summary["api_errors"] == 1


def test_t3(fake):
    host = profile.resolve_file(EXAMPLES / "hosts" / "win-web-01.yaml", [EXAMPLES / "bases"])
    assert checks.check_t3(agent(), host).passed
    bad = checks.check_t3(agent(name="Microsoft Windows 10 Pro", version="10.0.19045"), host)
    assert len(bad.problems) == 2
    assert checks.check_t3(None, host).problems == ["the manager does not know this agent"]
    old = agent()
    old["version"] = "Wazuh v4.14.9"
    assert "agent version" in checks.check_t3(old, host).problems[0]


def test_cli(fake, tmp_path, monkeypatch, capsys):
    fake.agent = agent()
    monkeypatch.setenv("WAZUH_API_PASSWORD", "secret")
    args = [
        "--manager",
        fake.url,
        "--profile",
        str(EXAMPLES / "hosts" / "win-web-01.yaml"),
        "--bases",
        str(EXAMPLES / "bases"),
    ]
    assert main(["t3", *args, "--json", str(tmp_path / "t3.json")]) == 0
    assert json.loads((tmp_path / "t3.json").read_text())["passed"] is True
    assert "T3: PASS" in capsys.readouterr().out
    log = tmp_path / "t2.jsonl"
    log.write_text(
        "".join(json.dumps(s) + "\n" for s in _samples((0, _ka(0)), (60, _ka(60)), (120, _ka(120))))
    )
    assert (
        main(["t2", "--agent", "x", "--from-log", str(log), "--duration", "2m", "--interval", "1m"])
        == 0
    )
    monkeypatch.delenv("WAZUH_API_PASSWORD")
    assert main(["t3", *args]) == 2
    assert "WAZUH_API_PASSWORD" in capsys.readouterr().err
