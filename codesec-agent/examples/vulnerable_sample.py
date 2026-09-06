"""Synthetic Flask service with one intentional vulnerability per rule
category this tool detects. Do not deploy this file — it exists purely as
a demo/test fixture for codesec-agent.
"""

import hashlib
import os
import pickle
import random
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "hunter2-prod-password"  # CWE-798: hardcoded credential
AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"  # CWE-798: hardcoded AWS key


@app.route("/backup")
def run_backup():
    target = request.args.get("target")
    os.system("tar czf /backups/out.tgz " + target)  # CWE-78: command injection
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)  # CWE-78: command injection
    return "ok"


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    cursor = get_cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # CWE-89: SQL injection
    return cursor.fetchall()


@app.route("/config")
def load_config():
    raw = request.args.get("data")
    return yaml.load(raw)  # CWE-502: unsafe deserialization


@app.route("/session")
def load_session():
    blob = request.args.get("session")
    return pickle.loads(blob)  # CWE-502: unsafe deserialization


@app.route("/compute")
def compute():
    expr = request.args.get("expr")
    return str(eval(expr))  # CWE-95: eval of untrusted input


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # CWE-327: weak hash


def generate_token():
    session_token = "".join(random.choice("abcdef0123456789") for _ in range(16))  # CWE-330
    return session_token


def fetch_internal(url):
    return requests.get(url, verify=False)  # CWE-295: disabled TLS verification


def read_upload(filename):
    return open(filename).read()  # CWE-22: path traversal (unvalidated parameter)


def get_cursor():
    raise NotImplementedError("stub for static analysis demo purposes")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # CWE-489: debug mode enabled in production
