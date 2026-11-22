import subprocess

import yaml
from flask import request


def search(cur):
    cur.execute("SELECT * FROM items WHERE name = %s", (request.args["q"],))


def run(host):
    subprocess.run(["ping", "-c1", host], check=True)


def load(text):
    return yaml.safe_load(text)
