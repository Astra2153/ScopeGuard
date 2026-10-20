import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WELL_KNOWN = "/.well-known/scopeguard-verification.txt"


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
