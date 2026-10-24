"""Local practice target for ScopeGuard demos. Binds to 127.0.0.1 only.

Switch its behaviour without restarting by writing "vulnerable" or "fixed" to lab_state/mode.
The demo script does this for you.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKENS = {"alice-token": "alice", "bob-token": "bob"}  # fake demo tokens
ORDERS = {
    "1001": {"id": "1001", "item": "Laptop", "owner": "alice"},
    "2002": {"id": "2002", "item": "Phone", "owner": "bob"},
}
STATE = Path(__file__).resolve().parent / "lab_state"


def read_state(name, default):
    try:
        return (STATE / name).read_text(encoding="ascii").strip() or default
    except OSError:
        return default


class Handler(BaseHTTPRequestHandler):
    def mode(self):
        return read_state("mode", "vulnerable")

    def version_string(self):
        # A version number in the Server header is a finding; the fixed mode removes it.
        return "LabTarget/0.1" if self.mode() == "vulnerable" else "LabTarget"

    def _send(self, status, body, content_type="text/plain", extra=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json")

    def _orders(self, order_id, mode):
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else ""
        user = TOKENS.get(token)
        if user is None:
            return self._json(401, {"error": "authentication required"})
        order = ORDERS.get(order_id)
        if order is None:
            return self._json(404, {"error": "not found"})
        if mode == "fixed" and order["owner"] != user:
            return self._json(404, {"error": "not found"})  # fixed: other people's orders look missing
        return self._json(200, order)  # vulnerable: any logged-in user can read any order

    def do_GET(self):
        mode = self.mode()
        path = self.path.split("?", 1)[0]
        if path == "/.well-known/scopeguard-verification.txt":
            token = read_state("token", "")
            if token:
                return self._send(200, token + "\n")
            return self._send(404, "not found")
        if path == "/":
            if mode == "fixed":
                extra = [
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("X-Frame-Options", "DENY"),
                    ("Referrer-Policy", "no-referrer"),
                    ("Set-Cookie", "sid=demo; Path=/; HttpOnly; SameSite=Lax"),
                ]
            else:
                extra = [("Set-Cookie", "sid=demo; Path=/")]
            return self._send(200, "<html>Lab target</html>", "text/html", extra)
        if path.startswith("/api/orders/"):
            return self._orders(path[len("/api/orders/"):], mode)
        return self._send(404, "not found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    STATE.mkdir(exist_ok=True)
    if not (STATE / "mode").exists():
        (STATE / "mode").write_text("vulnerable", encoding="ascii")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Lab target on http://127.0.0.1:{args.port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
