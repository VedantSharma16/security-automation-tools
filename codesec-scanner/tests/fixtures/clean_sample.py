import hashlib
import secrets
import subprocess

import requests
import yaml


def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def run_cmd(args):
    subprocess.run(["ls", "-la", *args], shell=False)


def safe_yaml(data):
    return yaml.safe_load(data)


def hash_for_integrity(payload):
    return hashlib.sha256(payload).hexdigest()


def generate_token():
    return secrets.token_urlsafe(32)


def fetch(url):
    return requests.get(url, verify=True)
