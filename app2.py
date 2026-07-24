"""Second sample with fresh vulnerabilities, to test detection on new code."""
import hashlib
import os
import sqlite3

DB_PASSWORD = "SuperSecretPassw0rd_hardcoded_123"  # hardcoded secret, Bandit B105


def weak_hash(data: str) -> str:
    # MD5 for security purposes -- Bandit B303.
    return hashlib.md5(data.encode()).hexdigest()


def lookup(user_id: str):
    conn = sqlite3.connect("app.db")
    # SQL injection via string formatting -- Bandit B608.
    conn.execute("SELECT * FROM users WHERE id = '%s'" % user_id)


def archive(path: str):
    # os.system with interpolation -- command injection, Bandit B605.
    os.system("gzip " + path)
