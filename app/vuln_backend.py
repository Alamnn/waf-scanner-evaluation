#!/usr/bin/env python3
"""Intentionally vulnerable backend application deployed behind ModSecurity + OWASP CRS."""
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def init_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT, secret TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'administrator', 'FLAG{SQLI_BACKEND_COMPROMISED}')")
    conn.execute("INSERT INTO users VALUES (2, 'alice', 'analyst', 'normal_user')")
    return conn


DB = init_db()


class VulnHandler(BaseHTTPRequestHandler):
    server_version = "VulnApp/1.0"

    def _send(self, code: int, body: str, ctype: str = "text/html"):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/":
            self._send(200, "<html><body><h1>Backend App</h1><a href='/user?id=1'>User</a> <a href='/search?q=laptop'>Search</a> <a href='/note?text=hello'>Note</a></body></html>")
            return

        if parsed.path == "/user":
            uid = qs.get("id", ["1"])[0]
            try:
                # Deliberate SQL injection vulnerability
                rows = DB.execute(f"SELECT id, username, role, secret FROM users WHERE id = {uid}").fetchall()
                self._send(200, f"User record: {rows}\n", "text/plain")
            except Exception as e:
                self._send(500, f"SQL Error: {e}\n", "text/plain")
            return

        if parsed.path == "/search":
            q = qs.get("q", [""])[0]
            # Deliberate reflected XSS vulnerability
            self._send(200, f"<html><body>Results for: {q}</body></html>")
            return

        if parsed.path == "/read":
            path = qs.get("file", ["readme.txt"])[0]
            # Deliberate path traversal / LFI simulation
            if "etc/passwd" in path or ".." in path:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
            else:
                self._send(200, "Welcome to the public readme file.\n", "text/plain")
            return

        if parsed.path == "/ping":
            host = qs.get("host", ["127.0.0.1"])[0]
            # Deliberate command injection simulation
            if any(c in host for c in [";", "|", "&", "$", "`", "id", "whoami"]):
                self._send(200, "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", "text/plain")
            else:
                self._send(200, f"PING {host}: 64 bytes from {host}: time=0.2ms\n", "text/plain")
            return

        if parsed.path == "/note":
            text = qs.get("text", [""])[0]
            self._send(200, f"Saved note: {text}\n", "text/plain")
            return

        self._send(404, "Not Found\n", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if self.path == "/api/comment":
            self._send(200, f"Stored comment: {raw}\n", "text/plain")
            return
        self._send(404, "Not Found\n", "text/plain")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8081), VulnHandler).serve_forever()
