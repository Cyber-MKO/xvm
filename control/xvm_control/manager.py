"""A small client for the Wazuh manager's REST API.

Only what the T2 and T3 checks need: log in, and read one agent. Endpoints
and fields follow Wazuh's public API reference (`POST
/security/user/authenticate`, `GET /agents`). The token is sent as a bearer
token and renewed when the manager answers 401.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class ManagerError(Exception):
    pass


class Manager:
    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        ca: str | None = None,
        insecure: bool = False,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
        self._auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.timeout = timeout
        self._token: str | None = None
        if self.url.startswith("https:"):
            self._ctx = ssl.create_default_context(cafile=ca)
            if insecure:
                # The manager's default certificate is self-signed.
                self._ctx.check_hostname = False
                self._ctx.verify_mode = ssl.CERT_NONE
        else:
            self._ctx = None

    def _request(self, method: str, path: str, headers: dict) -> dict:
        req = urllib.request.Request(self.url + path, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise
            raise ManagerError(f"{method} {path}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            raise ManagerError(f"{method} {path}: {e}") from e

    def login(self) -> None:
        try:
            body = self._request(
                "POST", "/security/user/authenticate", {"Authorization": f"Basic {self._auth}"}
            )
        except urllib.error.HTTPError as e:
            raise ManagerError("login refused: check the API user and password") from e
        token = (body.get("data") or {}).get("token")
        if not token:
            raise ManagerError("login answer has no token")
        self._token = token

    def get(self, path: str) -> dict:
        if self._token is None:
            self.login()
        try:
            return self._request("GET", path, {"Authorization": f"Bearer {self._token}"})
        except urllib.error.HTTPError:
            # The token expired: log in again once.
            self.login()
            try:
                return self._request("GET", path, {"Authorization": f"Bearer {self._token}"})
            except urllib.error.HTTPError as e:
                raise ManagerError(f"GET {path}: HTTP {e.code}") from e

    def agent(self, name: str) -> dict | None:
        """The agent with this name, or None if the manager does not know it."""
        q = urllib.parse.urlencode({"name": name})
        items = (self.get(f"/agents?{q}").get("data") or {}).get("affected_items") or []
        return next((a for a in items if a.get("name") == name), None)
