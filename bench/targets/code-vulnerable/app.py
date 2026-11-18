# Demo project that is DELIBERATELY VULNERABLE, for benchmarking scanners. Keys and data are fake.
import hashlib
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)
SECRET_KEY = "dev-super-secret-42"
DEBUG = True

db = sqlite3.connect("shop.db", check_same_thread=False)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return {"user": cur.fetchone()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Hello {name}</h1>")


@app.route("/import", methods=["POST"])
def import_cart():
    config = yaml.load(request.data)
    cart = pickle.loads(request.files["cart"].read())
    return {"ok": True, "config": str(config), "cart": len(cart)}


def register(email, password):
    digest = hashlib.md5(password.encode()).hexdigest()
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(16))
    return digest, reset_token


def supplier_prices():
    return requests.get("https://supplier.example/prices", verify=False).json()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
