"""The same demo shop, CONFIGURED WELL. It listens on 127.0.0.1 only.

Same pages as ../web-vulnerable/server.py, done safely: security headers, protected cookies, no sensitive files,
encoded search, parameterised queries, internal redirects only, a limit on sign-in attempts, no open API.
Every finding a scanner reports on this site is a false alarm.

Run: python server.py [port]   (default 8098)
"""
import html
import sqlite3
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT INTO products VALUES (1,'Running shoe',89.0),(2,'Hiking backpack',59.0),(3,'Water bottle',12.5);
""")
LOCK = threading.Lock()
ATTEMPTS = {}

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Safe shop</title>
<link rel="stylesheet" href="/static/style.css"><script src="/static/app.js"></script></head><body>
<h1>Safe shop</h1>
<nav><a href="/">Home</a> · <a href="/search?q=shoes">Search</a> · <a href="/product?id=1">Product</a> ·
<a href="/logout?next=/">Log out</a> · <a href="/login">Sign in</a></nav>
<form action="/search" method="get"><input name="q" value=""><button>Search</button></form>
{body}</body></html>"""

FILES = {
    "/static/app.js": ("text/javascript", "document.addEventListener('DOMContentLoaded', () => {});\n"),
    "/static/style.css": ("text/css", "body{font-family:system-ui;max-width:640px;margin:40px auto;color:#222}\n"),
    "/robots.txt": ("text/plain", "User-agent: *\nAllow: /\n"),
}

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head><body><h1>Sign in</h1>
<form method="post" action="/login"><input type="hidden" name="csrf" value="{csrf}">
<input name="email" type="email"><input name="password" type="password"><button>Sign in</button></form></body></html>"""

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; "
                               "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "web"
    sys_version = ""

    def log_message(self, *a):
        pass

    def version_string(self):
        return "web"

    def send(self, status, ctype, body, extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        if u.path == "/":
            return self.send(200, "text/html", PAGE.format(body="<p>Welcome!</p>"),
                             {"Set-Cookie": "session=abc123def456; Path=/; HttpOnly; Secure; SameSite=Lax"})
        if u.path == "/search":
            return self.send(200, "text/html", PAGE.format(body=f"<p>Results for {html.escape(q.get('q', ''))}</p>"))
        if u.path == "/product":
            pid = q.get("id", "1")
            if not pid.isdigit():
                return self.send(400, "text/html", PAGE.format(body="<p>Bad request</p>"))
            with LOCK:
                row = DB.execute("SELECT name, price FROM products WHERE id = ?", (int(pid),)).fetchone()
            body = f"<h2>{html.escape(row[0])}</h2><p>{row[1]} €</p>" if row else "<p>Not found</p>"
            return self.send(200 if row else 404, "text/html", PAGE.format(body=body))
        if u.path == "/logout":
            nxt = q.get("next", "/")
            return self.send(302, "text/html", "", {"Location": nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"})
        if u.path == "/login":
            return self.send(200, "text/html", LOGIN_PAGE.format(csrf="random-token"))
        if u.path in FILES:
            ctype, body = FILES[u.path]
            return self.send(200, ctype, body)
        return self.send(404, "text/html", PAGE.format(body="<p>Page not found</p>"))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(min(n, 65536))
        if self.path == "/login":
            ip = self.client_address[0]
            now = time.time()
            recent = [t for t in ATTEMPTS.get(ip, []) if now - t < 300]
            recent.append(now)
            ATTEMPTS[ip] = recent
            if len(recent) > 5:
                return self.send(429, "text/html", "<p>Too many attempts: try again in a few minutes.</p>", {"Retry-After": "300"})
            return self.send(200, "text/html", "<p>Wrong credentials.</p>" + LOGIN_PAGE.format(csrf="random-token"))
        return self.send(404, "text/plain", "not found")

    def do_OPTIONS(self):
        return self.send(405, "text/plain", "")


def start_background(port=8098):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="web-clean").start()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8098
    print(f"Well-configured demo shop on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
