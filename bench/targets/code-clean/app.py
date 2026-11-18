# Demo project WRITTEN WELL, for benchmarking scanners: no line here should become a finding.
# It has the same shape as ../code-vulnerable on purpose, but every point is done safely.
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, render_template, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
DEBUG = os.environ.get("DEBUG") == "1"

db = sqlite3.connect(os.environ.get("DB_PATH", "shop.db"), check_same_thread=False)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = db.cursor()
    cur.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return {"user": cur.fetchone()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return {"reachable": result.returncode == 0}


@app.route("/hello")
def hello():
    return render_template("hello.html", name=request.args.get("name", ""))


@app.route("/import", methods=["POST"])
def import_cart():
    config = yaml.safe_load(request.data)
    cart = json.loads(request.files["cart"].read())
    return {"ok": True, "entries": len(config or {}), "cart": len(cart)}


def register(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    reset_token = secrets.token_urlsafe(32)
    return salt + digest, reset_token


def valid_signature(data, signature):
    expected = hmac.new(os.environ["WEBHOOK_KEY"].encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def file_checksum(path):
    """Checksum of a downloaded file: it does not protect passwords."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def supplier_prices():
    return requests.get("https://supplier.example/prices", timeout=10).json()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=DEBUG)
