"""Deliberately vulnerable sample app used to demo codesec.

Do not deploy this. Every pattern below is intentionally insecure so the
scanner has something to find. See README.md for how to run it:

    codesec scan examples/vulnerable_app.py
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
db_password = "SuperSecretPassword123!"


def get_user(username: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # CWE-89: string-interpolated SQL
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()


def run_backup(target_dir: str):
    # CWE-78: shell=True with a dynamically built command
    subprocess.run("tar -czf backup.tgz " + target_dir, shell=True)


def load_config(path: str):
    with open(path) as fh:
        # CWE-502: unsafe YAML deserialization
        return yaml.load(fh, Loader=yaml.Loader)


def load_session(blob: bytes):
    # CWE-502: unpickling untrusted data
    return pickle.loads(blob)


def hash_password(password: str) -> str:
    # CWE-327: weak hash for password storage
    return hashlib.md5(password.encode()).hexdigest()


def generate_api_token() -> str:
    # CWE-330: predictable randomness for a security-sensitive value
    api_token = "".join(str(random.randint(0, 9)) for _ in range(32))
    return api_token


def fetch_internal(url: str):
    # CWE-295: disabled TLS verification
    return requests.get(url, verify=False)


def run_arbitrary(expr: str):
    # CWE-95: eval on external input
    return eval(expr)


@app.route("/whoami")
def whoami():
    name = request.args.get("name", "")
    # CWE-78: os.system with unsanitized input
    os.system("echo " + name)
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
