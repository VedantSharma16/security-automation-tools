import hashlib
import os
import pickle
import random
import subprocess

import requests
import yaml


def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()


def run_cmd(user_input):
    subprocess.run("ls " + user_input, shell=True)


def run_cmd_static():
    subprocess.run("ls -la", shell=True)


def unsafe_yaml(data):
    return yaml.load(data, Loader=yaml.Loader)


def unpickle(blob):
    return pickle.loads(blob)


def weak_hash(pw):
    return hashlib.sha1(pw.encode()).hexdigest()


def weak_token():
    secret_key = str(random.random())
    return secret_key


def insecure_request(url):
    return requests.get(url, verify=False)


def dangerous_eval(expr):
    return eval(expr)


def shell_command(cmd):
    os.system(cmd)
