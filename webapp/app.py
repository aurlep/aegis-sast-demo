"""Deliberately vulnerable web app for testing Aegis-generated DAST scans.

A tiny Flask app with a login and a few planted vulnerabilities behind it, so an
authenticated OWASP ZAP scan has something to find -- both passively (missing
security headers) and actively (reflected XSS, SQL injection).

    pip install flask
    python webapp.py    # serves on http://127.0.0.1:8080

Credentials: admin / admin  (wired to DAST_USERNAME / DAST_PASSWORD in CI).
Do not deploy this anywhere real.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, g, redirect, request, session

app = Flask(__name__)
app.secret_key = "insecure-hardcoded-secret"  # noqa: S105 - intentional test weakness


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        g.db.executemany(
            "INSERT INTO users VALUES (?, ?)", [(1, "admin"), (2, "alice"), (3, "bob")]
        )
    return g.db


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "admin":
            session["user"] = "admin"
            return redirect("/")
        return "Invalid credentials", 401
    # A standard username/password form so ZAP's browser auth auto-detects it.
    return """
    <html><body>
      <h1>Login</h1>
      <form method="post" action="/login">
        <input id="username" name="username" placeholder="username" />
        <input id="password" name="password" type="password" placeholder="password" />
        <button id="submit" type="submit">Sign in</button>
      </form>
    </body></html>
    """


def require_login():
    return "user" in session


@app.route("/")
def home():
    if not require_login():
        return redirect("/login")
    # "Sign out" is the logged-in marker ZAP verifies against.
    return """
    <html><body>
      <h1>Dashboard</h1>
      <a href="/login">Sign out</a>
      <ul>
        <li><a href="/search?q=hello">Search</a></li>
        <li><a href="/profile?id=1">Profile</a></li>
      </ul>
    </body></html>
    """


@app.route("/search")
def search():
    if not require_login():
        return redirect("/login")
    query = request.args.get("q", "")
    # Reflected XSS: the query is echoed into the page unescaped.
    return f"<html><body><h1>Results for {query}</h1></body></html>"


@app.route("/profile")
def profile():
    if not require_login():
        return redirect("/login")
    user_id = request.args.get("id", "1")
    # SQL injection: the id is interpolated straight into the query.
    cursor = db().execute(f"SELECT name FROM users WHERE id = {user_id}")  # noqa: S608
    rows = cursor.fetchall()
    return f"<html><body><h1>Profile</h1><p>{rows}</p></body></html>"


@app.teardown_appcontext
def close_db(_exc: object) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


if __name__ == "__main__":
    # Bind to all interfaces so the CI runner and ZAP container can reach it.
    app.run(host="0.0.0.0", port=8080)  # noqa: S104 - CI-only test app
