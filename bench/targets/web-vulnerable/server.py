"""Demo shop that is DELIBERATELY VULNERABLE. It listens on 127.0.0.1 only.

Use it to measure a web scanner without touching real systems. Never expose it to a network.
All data and keys are fake. Every flaw is listed in ../../expected.json.

Run: python server.py [port]   (default 8099)
"""
import html
import sqlite3
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT INTO products VALUES (1,'Running shoe',89.0),(2,'Hiking backpack',59.0),(3,'Water bottle',12.5);
""")
LOCK = threading.Lock()

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Demo shop</title>
<style>body{{font-family:system-ui;max-width:640px;margin:40px auto;color:#222}}a{{color:#1E40AF}}</style>
<script src="/static/app.js"></script><script src="/static/jquery-1.12.4.min.js"></script></head><body>
<h1>Demo shop</h1><p><em>Deliberately vulnerable benchmark target.</em></p>
<nav><a href="/">Home</a> · <a href="/search?q=shoes">Search</a> · <a href="/product?id=1">Product</a> ·
<a href="/logout?next=/">Log out</a> · <a href="/uploads/">Uploads</a> · <a href="/login">Sign in</a></nav>
<form action="/search" method="get"><input name="q" value=""><button>Search</button></form>
{body}</body></html>"""

FILES = {
    "/.env": ("text/plain", "APP_ENV=production\nDB_PASSWORD=DoNotUseThis123\nPAYMENT_KEY=sk_test_fake000000000000\n"),
    "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
    "/static/app.js": ("text/javascript", "console.log('shop');\n//# sourceMappingURL=app.js.map\n"),
    "/static/app.js.map": ("application/json", '{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}'),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /old-admin/\n"),
    "/uploads/": ("text/html", "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>"
                                "<a href='invoice-0042.pdf'>invoice-0042.pdf</a></body></html>"),
    "/old-admin/": ("text/html", "<html><body><h1>Old admin panel</h1><a href='/product?id=2'>product</a></body></html>"),
    "/static/jquery-1.12.4.min.js": ("text/javascript", "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(){};\n"),
    "/openapi.json": ("application/json", '{"openapi":"3.0.0","info":{"title":"Demo shop API","version":"1.0"},'
                      '"paths":{"/api/users":{"get":{"summary":"List users"}},"/api/products":{"get":{"summary":"Catalogue"}},'
                      '"/api/users/{id}":{"get":{"summary":"Detail"}}}}'),
    "/api/users": ("application/json", '[{"id":1,"email":"jane.doe@example.invalid","role":"admin"},{"id":2,"email":"john.roe@example.invalid","role":"customer"}]'),
    "/api/products": ("application/json", '[{"id":1,"name":"Running shoe"}]'),
}

LOGIN_PAGE = """<!doctype html><html><body><h1>Sign in</h1>
<form method="post" action="/login"><input type="hidden" name="csrf" value="demo-token">
<input name="email" type="email"><input name="password" type="password"><button>Sign in</button></form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.2.3"
    sys_version = ""

    def log_message(self, *a):
        pass

    def send(self, status, ctype, body, extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "DemoShop/2.4.1")      # version banner
        origin = self.headers.get("Origin")
        if origin:  # CORS that reflects any origin, with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()  # no CSP, no X-Frame-Options, no nosniff
        self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        if u.path == "/":
            # session cookie without HttpOnly, Secure or SameSite
            return self.send(200, "text/html", PAGE.format(body="<p>Welcome!</p>"), {"Set-Cookie": "session=abc123def456; Path=/"})
        if u.path == "/search":
            # reflected XSS: the parameter lands in the page without encoding
            return self.send(200, "text/html", PAGE.format(body=f"<p>Results for {q.get('q', '')}</p>"))
        if u.path == "/product":
            # SQL injection: direct concatenation, database error shown to the visitor
            try:
                with LOCK:
                    row = DB.execute("SELECT name, price FROM products WHERE id = " + q.get("id", "1")).fetchone()
                body = f"<h2>{html.escape(row[0])}</h2><p>{row[1]} €</p>" if row else "<p>Not found</p>"
                return self.send(200, "text/html", PAGE.format(body=body))
            except sqlite3.Error as e:
                return self.send(500, "text/html", PAGE.format(body=f"<pre>sqlite3.OperationalError: {html.escape(str(e))}</pre>"))
        if u.path == "/logout":
            # open redirect
            return self.send(302, "text/html", "", {"Location": q.get("next", "/")})
        if u.path == "/login":
            return self.send(200, "text/html", LOGIN_PAGE)
        if u.path in FILES:
            ctype, body = FILES[u.path]
            return self.send(200, ctype, body)
        return self.send(404, "text/html", PAGE.format(body="<p>Page not found</p>"))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(min(n, 65536)).decode("utf-8", "replace")
        if self.path == "/login":
            # no limit on attempts: always the same answer
            return self.send(200, "text/html", "<p>Wrong credentials.</p>" + LOGIN_PAGE)
        if self.path == "/graphql" and "__schema" in data:
            # GraphQL introspection left on
            return self.send(200, "application/json", '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Order"},{"name":"Mutation"}]}}}')
        return self.send(404, "text/plain", "not found")


def start_background(port=8099):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="web-vulnerable").start()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"Deliberately vulnerable demo shop on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
