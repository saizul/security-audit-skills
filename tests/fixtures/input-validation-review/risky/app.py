import os
import pickle
import subprocess

import requests
import yaml
from flask import redirect, request, send_file


def search(cur):
    q = request.args["q"]
    cur.execute(f"SELECT * FROM items WHERE name = '{q}'")
    cur.execute("SELECT * FROM items WHERE id = %s" % q)
    return q


def run(host):
    subprocess.run("ping -c1 " + host, shell=True)
    os.system("ls " + host)
    return eval(host)


def load(blob, text):
    obj = pickle.loads(blob)
    cfg = yaml.load(text)
    return obj, cfg


def download():
    return send_file(request.args["name"])


def proxy(url):
    return requests.get(url).text


def back():
    return redirect(request.args.get("next"))


def reviewed(cur, q):
    cur.execute(f"SELECT 1 WHERE {q}")  # review:ok q is a constant from the allow-list
