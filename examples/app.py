import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("shop.db", check_same_thread=False)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return {"user": cur.fetchone()}
