import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WELL_KNOWN = "/.well-known/scopeguard-verification.txt"
TOKENS = {"alice-token": "alice", "bob-token": "bob"}
ORDERS = {
    "1001": {"id": "1001", "item": "Laptop", "owner": "alice"},
    "2002": {"id": "2002", "item": "Phone", "owner": "bob"},
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def version_string(self):
        return "LabServer"  # no version digits, so the version-disclosure check stays quiet

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        items = headers.items() if isinstance(headers, dict) else (headers or [])
        for key, value in items:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj).encode(), {"Content-Type": "application/json"})

    def _api(self, path):
        srv = self.server
        auth = self.headers.get("Authorization")
        srv.auth_seen.append((path, auth, self.headers.get("Cookie")))
        if not path.startswith("/api/orders/"):
            self._send(404, b"nope")
            return
        order_id = path[len("/api/orders/"):]
        mode = srv.authz_mode
        if mode == "catchall":
            self._json(200, {"orders": "list"})  # ignores the id and the credentials
            return
        token = auth[7:].strip() if auth and auth.startswith("Bearer ") else None
        if mode != "anon" and token not in TOKENS:
            self._json(401, {"error": "authentication required"})
            return
        order = ORDERS.get(order_id)
        if order is None:
            self._json(404, {"error": "not found"})
            return
        if mode == "secure" and order["owner"] != TOKENS.get(token):
            self._json(404, {"error": "not found"})  # secure: someone else's order looks missing
            return
        self._json(200, order)

    def do_GET(self):
        srv = self.server
        srv.hits.append((self.command, self.path, self.headers.get("Host")))
        path = self.path
        if path == "/ok":
            self._send(200, b"hello")
        elif path == "/big":
            self._send(200, b"A" * 1_000_000)
        elif path == "/redir":
            self._send(302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})
        elif path == "/slow":
            time.sleep(3)
            self._send(200, b"late")
        elif path == WELL_KNOWN and srv.token is not None:
            self._send(200, (srv.token + "\n").encode())
        elif path == "/":
            headers = list(srv.root_headers)
            origin = self.headers.get("Origin")
            srv.origins_seen.append(origin)
            if srv.cors_reflect and origin:
                headers += [
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Credentials", "true"),
                ]
            self._send(200, b"<html>home</html>", headers)
        elif path == "/.git/HEAD" and "git" in srv.exposed:
            self._send(200, b"ref: refs/heads/main\n")
        elif path == "/.env" and "env" in srv.exposed:
            self._send(200, b"DB_PASSWORD=hunter2\nAPI_KEY=abc123\n")
        elif path.startswith("/api/"):
            self._api(path)
        else:
            self._send(404, b"nope")


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients that hang up early (size-cap test) are expected


class LabServer:
    def __init__(self):
        self.httpd = _Server(("127.0.0.1", 0), _Handler)
        self.httpd.hits = []
        self.httpd.token = None
        self.httpd.root_headers = []
        self.httpd.cors_reflect = False
        self.httpd.exposed = set()
        self.httpd.origins_seen = []
        self.httpd.authz_mode = "secure"  # secure | bola | anon | catchall
        self.httpd.auth_seen = []
        self.port = self.httpd.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"

    @property
    def hits(self):
        return self.httpd.hits

    @property
    def token(self):
        return self.httpd.token

    @token.setter
    def token(self, value):
        self.httpd.token = value

    def start(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        ).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
