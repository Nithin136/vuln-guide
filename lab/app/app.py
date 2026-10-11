"""VulnLab: a tiny INTENTIONALLY VULNERABLE web app for local security practice.

Two builds of the same code (set by the VARIANT environment variable):
  vulnerable : contains SQL injection, reflected XSS, IDOR and command injection
  patched    : the same four endpoints, fixed

DO NOT expose this to a network you do not control. Run it only on a local lab machine.
Every request is written as one JSON line so SIEM tools (Wazuh, Splunk) can detect attacks.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

from flask import Flask, g, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

VARIANT = os.environ.get("VARIANT", "vulnerable")
if VARIANT not in ("vulnerable", "patched"):
    sys.exit("VARIANT must be 'vulnerable' or 'patched'")
LOG_PATH = os.environ.get("LOG_PATH", f"/logs/app-{VARIANT}.json")
DB_PATH = os.environ.get("DB_PATH", "/tmp/lab.db")

app = Flask(__name__)
app.secret_key = "lab-only-not-a-real-secret"          # hardcoded on purpose: this is a lab
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

USERS = [(1, "admin", "S3cr3t!Admin", "admin"), (2, "priya", "priya123", "user"),
         (3, "ravi", "ravi@2024", "user"), (4, "sneha", "sneha@456", "user")]
ORDERS = [(1001, "priya", "Priya Sharma", "14 Garden Street", "+91 90000 00001", "Wireless mouse", 799),
          (1002, "ravi", "Ravi Kumar", "7 Lake View Road", "+91 90000 00002", "Laptop stand", 1499),
          (1003, "sneha", "Sneha Reddy", "52 Hill Colony", "+91 90000 00003", "Headphones", 2999),
          (1004, "admin", "Admin User", "1 Head Office", "+91 90000 00004", "Monitor", 8999),
          (1005, "ravi", "Ravi Kumar", "7 Lake View Road", "+91 90000 00002", "Keyboard", 1999),
          (1006, "priya", "Priya Sharma", "14 Garden Street", "+91 90000 00001", "Notebook set", 349)]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                 "password TEXT, password_hash TEXT, role TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, owner TEXT, name TEXT, "
                 "address TEXT, phone TEXT, item TEXT, total INTEGER)")
    for uid, name, pw, role in USERS:
        # 'password' (plaintext) is only read by the vulnerable build. The patched build uses the hash.
        conn.execute("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)", (uid, name, pw, generate_password_hash(pw), role))
    conn.executemany("INSERT OR IGNORE INTO orders VALUES (?,?,?,?,?,?,?)", ORDERS)
    conn.commit()
    conn.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.after_request
def log_and_harden(resp):
    params = {**request.args.to_dict(), **request.form.to_dict()}
    entry = {
        "app": "vulnlab", "variant": VARIANT,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "srcip": request.remote_addr, "method": request.method, "path": request.path,
        "params": "&".join(f"{k}={v}" for k, v in params.items())[:500],
        "status": resp.status_code, "http_status": resp.status_code, "user": session.get("user", "-"),
        "event": getattr(g, "event", "http"),
    }
    entry.update(getattr(g, "extra", {}))
    line = json.dumps(entry, ensure_ascii=False)
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass                                            # logging must never break the app
    if VARIANT == "patched":                            # defence in depth on every response
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'"
    return resp


def page(body, status=200):
    banner = ("INTENTIONALLY VULNERABLE BUILD: local lab use only" if VARIANT == "vulnerable"
              else "Patched build: same app, fixed")
    html = f"<!doctype html><meta charset=utf-8><title>VulnLab</title><h3>VulnLab ({VARIANT})</h3><small>{banner}</small><hr>{body}"
    return html, status


@app.route("/")
def index():
    g.event = "index"
    return page("<ul><li>POST /login (username, password)</li><li>GET /search?q=</li>"
                "<li>GET /api/orders/&lt;id&gt; (login first)</li><li>GET /tools/lookup?host=</li></ul>")


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    g.event = "login_failed"
    try:
        if VARIANT == "vulnerable":
            # VULNERABLE: user input is concatenated into the SQL text (SQL injection)
            row = db().execute("SELECT id, username, role FROM users WHERE username='%s' AND password='%s'" % (u, p)).fetchone()
        else:
            # FIXED: parameterized query + password hash comparison
            row = db().execute("SELECT id, username, role, password_hash FROM users WHERE username=?", (u,)).fetchone()
            if row is not None and not check_password_hash(row["password_hash"], p):
                row = None
    except sqlite3.Error as exc:
        g.event = "login_error"
        msg = f"Database error: {exc}" if VARIANT == "vulnerable" else "Something went wrong."
        return page(msg, 500)
    if row is None:
        return page("Invalid username or password.", 401)
    session["user"] = row["username"]
    g.event = "login_success"
    return page(f"Welcome {escape(row['username'])} (role: {row['role']})")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    g.event = "search"
    if VARIANT == "vulnerable":
        return page("<h4>Results for: " + q + "</h4>")        # VULNERABLE: raw input in HTML (reflected XSS)
    return page("<h4>Results for: " + str(escape(q)) + "</h4>")  # FIXED: output encoding (+ CSP header)


@app.route("/api/orders/<int:oid>")
def order(oid):
    g.event = "order_view"
    user = session.get("user")
    if not user:
        return {"error": "login required"}, 401
    row = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    g.extra = {"order_id": oid}
    if row is None:
        return {"error": "not found"}, 404
    cross = row["owner"] != user
    g.extra.update({"object_owner": row["owner"], "cross_user_access": cross})   # log the owner so cross-user access is detectable
    if VARIANT == "patched" and cross:
        return {"error": "forbidden"}, 403                  # FIXED: ownership check
    return {k: row[k] for k in ("id", "name", "address", "phone", "item", "total")}   # VULNERABLE build returns it to anyone logged in


@app.route("/tools/lookup")
def lookup():
    host = request.args.get("host", "")
    g.event = "lookup"
    if VARIANT == "vulnerable":
        # VULNERABLE: input is placed in a shell command (command injection)
        out = subprocess.run("getent hosts " + host, shell=True, capture_output=True, text=True, timeout=5)
    else:
        # FIXED: allow-list validation + argument list, no shell
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?", host):
            return page("Invalid host name.", 400)
        out = subprocess.run(["getent", "hosts", host], shell=False, capture_output=True, text=True, timeout=5)
    return (out.stdout + out.stderr or "(no result)\n"), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/healthz")
def healthz():
    g.event = "health"
    return "ok"
